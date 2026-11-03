"""Tests de la tokenisation du PAN (FF3-1)."""
import pytest

from secumon.gateway.tokenization import PanTokenizer, TokenizationError

KEY = "00" * 32          # cle de TEST
OTHER_KEY = "11" * 32
PAN = "4111111111111111"  # carte de test Visa


@pytest.fixture
def tokenizer():
    return PanTokenizer(KEY)


def test_token_conserve_format_bin_et_4_derniers(tokenizer):
    token = tokenizer.tokenize(PAN)
    assert len(token) == len(PAN) and token.isdigit()
    assert token[:6] == PAN[:6] and token[-4:] == PAN[-4:]
    assert token != PAN


def test_detokenisation_redonne_le_pan(tokenizer):
    assert tokenizer.detokenize(tokenizer.tokenize(PAN)) == PAN


def test_meme_carte_meme_token(tokenizer):
    # Indispensable pour que l'IA suive le comportement d'une carte dans le temps
    assert tokenizer.tokenize(PAN) == tokenizer.tokenize(PAN)


def test_cartes_differentes_tokens_differents(tokenizer):
    assert tokenizer.tokenize(PAN) != tokenizer.tokenize("4111112222221111")


def test_cle_differente_token_different(tokenizer):
    assert tokenizer.tokenize(PAN) != PanTokenizer(OTHER_KEY).tokenize(PAN)


def test_pan_trop_court_refuse(tokenizer):
    with pytest.raises(TokenizationError):
        tokenizer.tokenize("4111111111111")  # 13 chiffres : seulement 3 au milieu


def test_pan_non_numerique_refuse(tokenizer):
    with pytest.raises(TokenizationError):
        tokenizer.tokenize("4111-1111-1111-1111")
