"""Tokenisation du PAN (M2) : FF3-1 (NIST SP 800-38G Rev.1), BIN et 4 derniers conserves."""
import hashlib
import os

from ff3 import FF3Cipher

TOKEN_KEY_ENV = "SECUMON_TOKEN_KEY"  # nosec B105 - nom de variable, pas un secret
KEEP_FIRST, KEEP_LAST = 6, 4   # BIN + 4 derniers chiffres restent visibles
MIN_MIDDLE = 6                 # NIST : domaine >= 10^6 pour la base 10


class TokenizationError(ValueError):
    """PAN invalide ou trop court pour etre tokenise."""


def load_token_key() -> str:
    """Cle AES-256 (64 caracteres hex), DISTINCTE de la cle MAC (separation des cles)."""
    value = os.environ.get(TOKEN_KEY_ENV, "")
    if len(value) != 64:
        raise RuntimeError(f"{TOKEN_KEY_ENV} absente ou invalide : 32 octets attendus (voir .env.example)")
    bytes.fromhex(value)  # leve ValueError si ce n'est pas de l'hexadecimal
    return value


class PanTokenizer:
    def __init__(self, key_hex: str):
        self.key_hex = key_hex

    def _split(self, pan: str) -> tuple[str, str, str]:
        if not pan.isdigit():
            raise TokenizationError("le PAN doit contenir uniquement des chiffres")
        head, middle, tail = pan[:KEEP_FIRST], pan[KEEP_FIRST:-KEEP_LAST], pan[-KEEP_LAST:]
        if len(middle) < MIN_MIDDLE:
            raise TokenizationError(f"PAN trop court ({len(pan)} chiffres) pour une tokenisation FF3-1")
        return head, middle, tail

    def _cipher(self, head: str, tail: str) -> FF3Cipher:
        # Tweak (56 bits pour FF3-1) derive du BIN + 4 derniers : public mais propre a chaque carte
        tweak = hashlib.sha256(f"{head}|{tail}".encode()).hexdigest()[:14]
        return FF3Cipher(self.key_hex, tweak)

    def tokenize(self, pan: str) -> str:
        head, middle, tail = self._split(pan)
        return head + self._cipher(head, tail).encrypt(middle) + tail

    def detokenize(self, token: str) -> str:
        head, middle, tail = self._split(token)
        return head + self._cipher(head, tail).decrypt(middle) + tail
