"""Gestion des cles (M3) - version provisoire, avant le passage a SoftHSM2."""
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MASTER_KEY_ENV = "SECUMON_MAC_MASTER_KEY"


def load_master_key() -> bytes:
    """Lit la cle maitre (32 octets, en hexadecimal) depuis l'environnement."""
    value = os.environ.get(MASTER_KEY_ENV)
    if not value:
        raise RuntimeError(f"{MASTER_KEY_ENV} absente : creez le fichier .env (voir .env.example)")
    key = bytes.fromhex(value)
    if len(key) != 32:
        raise RuntimeError(f"{MASTER_KEY_ENV} doit faire 32 octets (64 caracteres hexadecimaux)")
    return key


def terminal_mac_key(master_key: bytes, terminal_id: str) -> bytes:
    """Derive une cle MAC AES-128 (TAK) unique par terminal avec HKDF-SHA256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b"SECUMON-TAK|" + terminal_id.encode(),
    ).derive(master_key)
