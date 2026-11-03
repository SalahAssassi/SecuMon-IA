"""Tests d'integration HSM (SoftHSM2) : ignores si le HSM n'est pas configure."""
import os
import secrets

import pytest

from secumon.common.config import load_dotenv

load_dotenv()
pytestmark = pytest.mark.skipif(not os.environ.get("SECUMON_HSM_PIN"),
                                reason="HSM non configure (SECUMON_HSM_PIN absent)")

import pkcs11  # noqa: E402
from pkcs11 import Attribute  # noqa: E402

from secumon.gateway.replay import ReplayGuard  # noqa: E402
from secumon.gateway.server import process_message  # noqa: E402
from secumon.hsm.hsm import Hsm, HsmKeyNotFound  # noqa: E402
from secumon.iso8583.mac import kcv, sign_message, verify_and_decode  # noqa: E402
from secumon.iso8583.messages import build_auth_request  # noqa: E402

TEST_ID = "PYTEST01"  # 8 caracteres, comme un DE41


class FakeStore:
    def __init__(self):
        self.data = {}

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.data:
            return None
        self.data[key] = value
        return True


@pytest.fixture
def hsm():
    with Hsm.from_env(rw=True) as h:
        h.delete_terminal_key(TEST_ID)
        yield h
        h.delete_terminal_key(TEST_ID)   # le HSM reste propre apres les tests


def test_kcv_identique_terminal_et_hsm(hsm):
    value = secrets.token_bytes(16)
    assert kcv(hsm.import_terminal_key(TEST_ID, value)) == kcv(value)


def test_terminal_signe_en_logiciel_passerelle_verifie_dans_hsm(hsm):
    value = secrets.token_bytes(16)
    hsm_key = hsm.import_terminal_key(TEST_ID, value)
    request = build_auth_request("4111111111111111", 15000, TEST_ID, "MERCHANT0000001")
    raw = sign_message(request, value)                       # cote terminal (logiciel)
    response = process_message(raw, TEST_ID, hsm_key, ReplayGuard(FakeStore()))
    assert verify_and_decode(response, value)["39"] == "00"  # reponse signee par le HSM


def test_cle_non_extractible(hsm):
    key = hsm.import_terminal_key(TEST_ID, secrets.token_bytes(16))._key
    assert key[Attribute.SENSITIVE] is True
    assert key[Attribute.EXTRACTABLE] is False
    with pytest.raises(pkcs11.PKCS11Error):
        key[Attribute.VALUE]


def test_cle_mac_usage_limite_au_mac(hsm):
    # Politique lue DANS le HSM (C_GetAttributeValue), pas dans la bibliotheque Python
    key = hsm.import_terminal_key(TEST_ID, secrets.token_bytes(16))._key
    assert key[Attribute.SIGN] is True and key[Attribute.VERIFY] is True
    for forbidden in (Attribute.ENCRYPT, Attribute.DECRYPT, Attribute.WRAP,
                      Attribute.UNWRAP, Attribute.DERIVE):
        assert key[forbidden] is False, f"usage interdit active : {forbidden.name}"


def test_terminal_inconnu_refuse(hsm):
    with pytest.raises(HsmKeyNotFound):
        hsm.terminal_key("INCONNU1")


# --- PIN block dans le HSM --------------------------------------------------
from secumon.hsm.pinblock import SoftwareAes, decode, encode, translate  # noqa: E402

PIN_TEST_LABELS = ("TPK-PYTEST01", "TPK-PYTEST02")


@pytest.fixture
def pin_hsm():
    with Hsm.from_env(rw=True) as h:
        for label in PIN_TEST_LABELS:
            h.delete_key(label)
        yield h
        for label in PIN_TEST_LABELS:
            h.delete_key(label)


def test_traduction_pin_dans_le_hsm(pin_hsm):
    src, dst = secrets.token_bytes(16), secrets.token_bytes(16)
    hsm_src = pin_hsm.import_terminal_pin_key("PYTEST01", src)
    hsm_dst = pin_hsm.import_terminal_pin_key("PYTEST02", dst)
    block = encode("1234", "4111111111111111", SoftwareAes(src))      # terminal (logiciel)
    translated = translate(block, "4111111111111111", hsm_src, hsm_dst)  # passerelle (HSM)
    assert decode(translated, "4111111111111111", SoftwareAes(dst)) == "1234"


def test_cle_pin_ne_peut_pas_signer(pin_hsm):
    key = pin_hsm.import_terminal_pin_key("PYTEST01", secrets.token_bytes(16))._key
    assert key[Attribute.ENCRYPT] is True and key[Attribute.DECRYPT] is True
    assert key[Attribute.SIGN] is False and key[Attribute.VERIFY] is False
