"""Integrite des messages ISO 8583 : MAC AES-CMAC place dans DE64."""
import hmac

from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.cmac import CMAC

from secumon.iso8583.messages import decode_message, encode_message

MAC_BYTES = 8                 # MAC = 8 octets (AES-CMAC tronque)
DE64_LEN = MAC_BYTES * 2      # DE64 (spec ASCII) = 16 caracteres hexadecimaux


class MacError(Exception):
    """MAC absent, mal place ou invalide."""


def compute_mac(key: bytes, data: bytes) -> bytes:
    """AES-CMAC tronque a 8 octets, renvoye en 16 caracteres hexadecimaux ASCII."""
    cmac = CMAC(algorithms.AES(key))
    cmac.update(data)
    return cmac.finalize()[:MAC_BYTES].hex().upper().encode("ascii")


def sign_message(doc: dict, key: bytes) -> bytes:
    """Encode le message avec DE64 = AES-CMAC(cle, tout le message avant le MAC)."""
    doc = {k: v for k, v in doc.items() if k not in ("p", "64")}
    doc["64"] = "0" * DE64_LEN              # place reservee : active le bit 64 du bitmap
    body = encode_message(doc)[:-DE64_LEN]  # DE64 est le dernier champ : on retire la place reservee
    return body + compute_mac(key, body)


def verify_and_decode(raw: bytes, key: bytes) -> dict:
    """Verifie le MAC puis renvoie le message decode. Leve MacError si invalide."""
    doc = decode_message(raw)  # peut lever iso8583.DecodeError (message malforme)
    if "64" not in doc:
        raise MacError("MAC absent (DE64)")
    if "1" in doc:
        raise MacError("bitmap secondaire non supporte avec DE64")
    body, mac = raw[:-DE64_LEN], raw[-DE64_LEN:]
    if not hmac.compare_digest(compute_mac(key, body), mac):
        raise MacError("MAC invalide : message altere ou mauvaise cle")
    return doc
