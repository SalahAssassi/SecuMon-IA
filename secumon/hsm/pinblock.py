"""PIN block ISO 9564-1 format 4 (AES) : le PIN ne circule jamais en clair.
Le chiffrement est delegue a un moteur AES (logiciel cote terminal, HSM cote passerelle)."""
import secrets

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK = 16


class PinBlockError(ValueError):
    """PIN invalide, PAN invalide ou PIN block incoherent (mauvaise cle, mauvaise carte)."""


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _pin_field(pin: str) -> bytes:
    if not (pin.isdigit() and 4 <= len(pin) <= 12):
        raise PinBlockError("le PIN doit contenir de 4 a 12 chiffres")
    nibbles = ("4" + format(len(pin), "X") + pin).ljust(16, "A")
    return bytes.fromhex(nibbles) + secrets.token_bytes(8)


def _pan_field(pan: str) -> bytes:
    if not pan.isdigit() or len(pan) > 19:
        raise PinBlockError("PAN invalide")
    digits = pan.rjust(12, "0")
    return bytes.fromhex((format(len(digits) - 12, "X") + digits).ljust(32, "0"))


def encode(pin: str, pan: str, cipher) -> bytes:
    """Construit le PIN block (16 octets) a partir du PIN et du PAN."""
    intermediate = cipher.encrypt_block(_pin_field(pin))
    return cipher.encrypt_block(_xor(intermediate, _pan_field(pan)))


def decode(block: bytes, pan: str, cipher) -> str:
    """Retrouve le PIN. Leve PinBlockError si la cle ou la carte ne correspondent pas."""
    if len(block) != BLOCK:
        raise PinBlockError("PIN block de taille invalide")
    intermediate = _xor(cipher.decrypt_block(block), _pan_field(pan))
    field = cipher.decrypt_block(intermediate)[:8].hex().upper()
    if field[0] != "4":
        raise PinBlockError("format de PIN block inconnu (mauvaise cle ou mauvaise carte)")
    length = int(field[1], 16)
    pin, fill = field[2:2 + length], field[2 + length:]
    if not (4 <= length <= 12 and pin.isdigit() and set(fill) <= {"A"}):
        raise PinBlockError("PIN block incoherent (mauvaise cle ou mauvaise carte)")
    return pin


def translate(block: bytes, pan: str, source, target) -> bytes:
    """Traduction de cle (role de l'acquereur) : TPK du terminal -> ZPK inter-bancaire."""
    return encode(decode(block, pan, source), pan, target)


class SoftwareAes:
    """Moteur AES logiciel (cote terminal) : un seul bloc de 16 octets a la fois,
    primitive exigee par ISO 9564 format 4 (et non le mode ECB applique a un message)."""

    def __init__(self, key: bytes):
        self._cipher = Cipher(algorithms.AES(key), modes.ECB())  # nosemgrep  # nosec B305

    def encrypt_block(self, data: bytes) -> bytes:
        enc = self._cipher.encryptor()
        return enc.update(data) + enc.finalize()

    def decrypt_block(self, data: bytes) -> bytes:
        dec = self._cipher.decryptor()
        return dec.update(data) + dec.finalize()


def pin_key_kcv(cipher) -> str:
    """KCV classique d'une cle de chiffrement : 3 premiers octets de AES(cle, bloc de zeros)."""
    return cipher.encrypt_block(bytes(BLOCK))[:3].hex().upper()
