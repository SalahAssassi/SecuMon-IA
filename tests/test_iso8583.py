"""Tests ISO 8583, MAC DE64 et traitement de la passerelle."""
import iso8583
import pytest

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


# --- Passerelle -------------------------------------------------------------
def test_passerelle_approuve_transaction_legitime():
    assert response_code(process_message(signed("TPE-0001"), "TPE-0001", KEY)) == "00"


def test_passerelle_detecte_usurpation_de_terminal():
    assert response_code(process_message(signed("GAB-0001"), "TPE-0001", KEY)) == "63"


def test_passerelle_detecte_message_altere():
    tampered = signed().replace(AMOUNT_150, AMOUNT_FORGED, 1)
    assert response_code(process_message(tampered, "TPE-0001", KEY)) == "63"


def test_passerelle_refuse_message_sans_mac():
    unsigned = encode_message(make_request())
    assert response_code(process_message(unsigned, "TPE-0001", KEY)) == "63"


def test_passerelle_rejette_message_malforme():
    assert response_code(process_message(b"\x00\x01garbage", "TPE-0001", KEY)) == "30"