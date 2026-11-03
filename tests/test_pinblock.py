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
