"""Tests ISO 8583, MAC DE64, anti-rejeu et traitement de la passerelle."""
from datetime import datetime, timedelta, timezone

import iso8583
import pytest

from secumon.gateway.replay import ReplayGuard, parse_de7
from secumon.gateway.server import process_message
from secumon.hsm.keys import terminal_mac_key
from secumon.iso8583.mac import MacError, sign_message, verify_and_decode
from secumon.iso8583.messages import (
    build_auth_request, build_auth_response, decode_message, encode_message, mask_pan,
)

TEST_PAN = "4111111111111111"      # carte de test Visa, aucune valeur reelle
KEY = bytes(range(16))             # cle de TEST
OTHER_KEY = bytes(16)
AMOUNT_150 = b"000000015000"
AMOUNT_FORGED = b"000099999900"


class FakeStore:
    """Imite redis.set(key, value, nx=True, ex=...) en memoire."""

    def __init__(self):
        self.data = {}

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.data:
            return None
        self.data[key] = value
        return True


@pytest.fixture
def guard():
    return ReplayGuard(FakeStore())


def make_request(terminal_id="TPE-0001"):
    return build_auth_request(TEST_PAN, 15000, terminal_id, "MERCHANT0000001")


def signed(terminal_id="TPE-0001", key=KEY):
    return sign_message(make_request(terminal_id), key)


def response_code(raw_response):
    return verify_and_decode(raw_response, KEY)["39"]


# --- ISO 8583 ---------------------------------------------------------------
def test_encode_decode_aller_retour():
    request = make_request()
    decoded = decode_message(encode_message(request))
    for field in ("t", "2", "3", "4", "11", "41", "49"):
        assert decoded[field] == request[field]


def test_mask_pan():
    assert mask_pan(TEST_PAN) == "411111******1111"


def test_reponse_ne_renvoie_pas_le_pan():
    response = build_auth_response(make_request(), "00")
    assert response["39"] == "00"
    assert "2" not in response


def test_message_malforme_leve_une_erreur():
    with pytest.raises(iso8583.DecodeError):
        decode_message(b"ceci n'est pas un message ISO 8583")


# --- MAC DE64 ---------------------------------------------------------------
def test_mac_valide_accepte():
    assert verify_and_decode(signed(), KEY)["41"].strip() == "TPE-0001"


def test_mac_detecte_montant_modifie():
    tampered = signed().replace(AMOUNT_150, AMOUNT_FORGED, 1)
    with pytest.raises(MacError):
        verify_and_decode(tampered, KEY)


def test_mac_refuse_mauvaise_cle():
    with pytest.raises(MacError):
        verify_and_decode(signed(key=OTHER_KEY), KEY)


def test_mac_absent_refuse():
    with pytest.raises(MacError):
        verify_and_decode(encode_message(make_request()), KEY)


def test_cles_differentes_par_terminal():
    master = bytes(32)
    assert terminal_mac_key(master, "TPE-0001") != terminal_mac_key(master, "TPE-0002")
    assert terminal_mac_key(master, "TPE-0001") == terminal_mac_key(master, "TPE-0001")


# --- Anti-rejeu -------------------------------------------------------------
def test_parse_de7_passage_d_annee():
    now = datetime(2027, 1, 1, 0, 0, 30, tzinfo=timezone.utc)
    assert parse_de7("1231235950", now).year == 2026


def test_rejeu_detecte(guard):
    raw = signed()
    assert response_code(process_message(raw, "TPE-0001", KEY, guard)) == "00"
    assert response_code(process_message(raw, "TPE-0001", KEY, guard)) == "94"


def test_message_perime_refuse(guard):
    request = make_request()
    request["7"] = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%m%d%H%M%S")
    raw = sign_message(request, KEY)
    assert response_code(process_message(raw, "TPE-0001", KEY, guard)) == "63"


def test_transactions_distinctes_acceptees(guard):
    assert response_code(process_message(signed(), "TPE-0001", KEY, guard)) == "00"
    assert response_code(process_message(signed(), "TPE-0001", KEY, guard)) == "00"


# --- Passerelle -------------------------------------------------------------
def test_passerelle_approuve_transaction_legitime(guard):
    assert response_code(process_message(signed("TPE-0001"), "TPE-0001", KEY, guard)) == "00"


def test_passerelle_detecte_usurpation_de_terminal(guard):
    assert response_code(process_message(signed("GAB-0001"), "TPE-0001", KEY, guard)) == "63"


def test_passerelle_detecte_message_altere(guard):
    tampered = signed().replace(AMOUNT_150, AMOUNT_FORGED, 1)
    assert response_code(process_message(tampered, "TPE-0001", KEY, guard)) == "63"


def test_passerelle_refuse_message_sans_mac(guard):
    unsigned = encode_message(make_request())
    assert response_code(process_message(unsigned, "TPE-0001", KEY, guard)) == "63"


def test_passerelle_rejette_message_malforme(guard):
    assert response_code(process_message(b"\x00\x01garbage", "TPE-0001", KEY, guard)) == "30"