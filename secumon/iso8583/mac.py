"""Integrite des messages ISO 8583 : MAC AES-CMAC place dans DE64.
La cle peut etre logicielle (bytes, cote terminal) ou une cle HSM (methode cmac, cote passerelle)."""
import hmac

from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.cmac import CMAC

from secumon.iso8583.messages import decode_message, encode_message

MAC_BYTES = 8                 # MAC = 8 octets (AES-CMAC tronque)
DE64_LEN = MAC_BYTES * 2      # DE64 (spec ASCII) = 16 caracteres hexadecimaux


class MacError(Exception):
    """MAC absent, mal place ou invalide."""


def raw_cmac(key, data: bytes) -> bytes:
    """AES-CMAC complet (16 octets), calcule dans le HSM si 'key' est une cle HSM."""
    if hasattr(key, "cmac"):
        return key.cmac(data)
    cmac = CMAC(algorithms.AES(key))
    cmac.update(data)
    return cmac.finalize()


def compute_mac(key, data: bytes) -> bytes:
    """AES-CMAC tronque a 8 octets, renvoye en 16 caracteres hexadecimaux ASCII."""
    return raw_cmac(key, data)[:MAC_BYTES].hex().upper().encode("ascii")


def kcv(key) -> str:
    """Key Check Value : empreinte publique de 3 octets pour comparer deux cles sans les reveler."""
    return raw_cmac(key, bytes(16))[:3].hex().upper()


def sign_message(doc: dict, key) -> bytes:
    """Encode le message avec DE64 = AES-CMAC(cle, tout le message avant le MAC)."""
    doc = {k: v for k, v in doc.items() if k not in ("p", "64")}
    doc["64"] = "0" * DE64_LEN
    body = encode_message(doc)[:-DE64_LEN]
    return body + compute_mac(key, body)


def verify_and_decode(raw: bytes, key) -> dict:
    """Verifie le MAC puis renvoie le message decode. Leve MacError si invalide."""
    doc = decode_message(raw)
    if "64" not in doc:
        raise MacError("MAC absent (DE64)")
    if "1" in doc:
        raise MacError("bitmap secondaire non supporte avec DE64")
    body, mac = raw[:-DE64_LEN], raw[-DE64_LEN:]
    if not hmac.compare_digest(compute_mac(key, body), mac):
        raise MacError("MAC invalide : message altere ou mauvaise cle")
    return doc
