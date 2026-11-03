"""Tests du PIN block ISO 9564-1 format 4."""
import secrets

import pytest

from secumon.hsm.pinblock import PinBlockError, SoftwareAes, decode, encode, translate

PAN = "4111111111111111"   # carte de test
PIN = "1234"               # PIN de test


@pytest.fixture
def tpk():
    return SoftwareAes(secrets.token_bytes(16))


def test_aller_retour(tpk):
    assert decode(encode(PIN, PAN, tpk), PAN, tpk) == PIN


def test_meme_pin_blocs_differents_a_chaque_transaction(tpk):
    # Les 8 octets aleatoires empechent de comparer ou rejouer des blocs
    assert encode(PIN, PAN, tpk) != encode(PIN, PAN, tpk)


def test_bloc_ne_contient_pas_le_pin_en_clair(tpk):
    assert PIN not in encode(PIN, PAN, tpk).hex()


def test_mauvaise_cle_detectee(tpk):
    with pytest.raises(PinBlockError):
        decode(encode(PIN, PAN, tpk), PAN, SoftwareAes(secrets.token_bytes(16)))


def test_mauvaise_carte_detectee(tpk):
    with pytest.raises(PinBlockError):
        decode(encode(PIN, PAN, tpk), "4111112222221111", tpk)


def test_traduction_tpk_vers_zpk(tpk):
    zpk = SoftwareAes(secrets.token_bytes(16))
    translated = translate(encode(PIN, PAN, tpk), PAN, tpk, zpk)
    assert decode(translated, PAN, zpk) == PIN


@pytest.mark.parametrize("bad_pin", ["123", "1234567890123", "12a4", ""])
def test_pin_invalide_refuse(tpk, bad_pin):
    with pytest.raises(PinBlockError):
        encode(bad_pin, PAN, tpk)


# --- Passerelle : traduction du PIN block (DE52) ---------------------------
from secumon.gateway.replay import ReplayGuard  # noqa: E402
from secumon.gateway.server import process_message  # noqa: E402
from secumon.iso8583.mac import sign_message, verify_and_decode  # noqa: E402
from secumon.iso8583.messages import build_auth_request  # noqa: E402

MAC_KEY = bytes(range(16))  # cle MAC de TEST


class FakeStore:
    def __init__(self):
        self.data = {}

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.data:
            return None
        self.data[key] = value
        return True


def _signed_request_with_pin(block: bytes) -> bytes:
    request = build_auth_request(PAN, 15000, "TPE-0001", "MERCHANT0000001")
    request["52"] = block.hex().upper()
    return sign_message(request, MAC_KEY)


def test_passerelle_accepte_pin_block_valide(tpk):
    zpk = SoftwareAes(secrets.token_bytes(16))
    raw = _signed_request_with_pin(encode(PIN, PAN, tpk))
    response = process_message(raw, "TPE-0001", MAC_KEY, ReplayGuard(FakeStore()), pin_keys=(tpk, zpk))
    decoded = verify_and_decode(response, MAC_KEY)
    assert decoded["39"] == "00"
    assert "52" not in decoded  # le PIN block n'est jamais renvoye


def test_passerelle_refuse_pin_block_forge(tpk):
    zpk = SoftwareAes(secrets.token_bytes(16))
    forged = encode(PIN, PAN, SoftwareAes(secrets.token_bytes(16)))  # cle inconnue
    raw = _signed_request_with_pin(forged)
    response = process_message(raw, "TPE-0001", MAC_KEY, ReplayGuard(FakeStore()), pin_keys=(tpk, zpk))
    assert verify_and_decode(response, MAC_KEY)["39"] == "81"
