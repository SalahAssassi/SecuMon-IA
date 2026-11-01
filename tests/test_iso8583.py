"""Tests du module ISO 8583 et du traitement de la passerelle."""
import iso8583
import pytest

from secumon.gateway.server import process_message
from secumon.iso8583.messages import (
    build_auth_request, build_auth_response, decode_message, encode_message, mask_pan,
)

TEST_PAN = "4111111111111111"  # carte de test Visa, aucune valeur reelle


def make_request(terminal_id="TPE-0001"):
    return build_auth_request(TEST_PAN, 15000, terminal_id, "MERCHANT0000001")


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


def test_passerelle_approuve_transaction_legitime():
    raw = encode_message(make_request("TPE-0001"))
    assert decode_message(process_message(raw, "TPE-0001"))["39"] == "00"


def test_passerelle_detecte_usurpation_de_terminal():
    raw = encode_message(make_request("GAB-0001"))
    assert decode_message(process_message(raw, "TPE-0001"))["39"] == "63"


def test_passerelle_rejette_message_malforme():
    assert decode_message(process_message(b"\x00\x01garbage", "TPE-0001"))["39"] == "30"
