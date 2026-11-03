"""Construction, encodage et decodage des messages ISO 8583 de SecuMon-IA."""
import copy
import secrets
from datetime import datetime, timezone

import iso8583
from iso8583.specs import default_ascii

SPEC = copy.deepcopy(default_ascii)
# DE52 : PIN block AES (ISO 9564-1 format 4) = 16 octets, transmis en 32 caracteres hex.
# Adaptation du champ 64 bits historique (ISO 8583:1987) a un bloc AES de 128 bits.
SPEC["52"] = {**SPEC["64"], "max_len": 32, "desc": "PIN Data (ISO 9564-1 format 4)"}

MTI_AUTH_REQUEST = "0100"
MTI_AUTH_RESPONSE = "0110"

RC_APPROVED = "00"            # transaction approuvee
RC_FORMAT_ERROR = "30"        # erreur de format
RC_SECURITY_VIOLATION = "63"  # violation de securite

# Champs recopies dans la reponse. Le PAN (DE2) n'est volontairement PAS renvoye :
# principe de minimisation des donnees sensibles.
ECHO_FIELDS = ("3", "4", "7", "11", "12", "13", "41", "42", "49")


def new_stan() -> str:
    """STAN : numero de trace sur 6 chiffres, genere de facon cryptographiquement sure."""
    return f"{secrets.randbelow(1_000_000):06d}"


def build_auth_request(pan: str, amount_cents: int, terminal_id: str, merchant_id: str,
                       mcc: str = "5411", currency: str = "504", entry_mode: str = "051") -> dict:
    """Construit une demande d'autorisation 0100."""
    now = datetime.now(timezone.utc)
    return {
        "t": MTI_AUTH_REQUEST,
        "2": pan,
        "3": "000000",
        "4": f"{amount_cents:012d}",
        "7": now.strftime("%m%d%H%M%S"),
        "11": new_stan(),
        "12": now.strftime("%H%M%S"),
        "13": now.strftime("%m%d"),
        "18": mcc,
        "22": entry_mode,
        "41": terminal_id.ljust(8)[:8],
        "42": merchant_id.ljust(15)[:15],
        "49": currency,
    }


def build_auth_response(request: dict, response_code: str) -> dict:
    """Construit la reponse 0110 correspondant a une demande 0100."""
    response = {"t": MTI_AUTH_RESPONSE, "39": response_code}
    for field in ECHO_FIELDS:
        if field in request:
            response[field] = request[field]
    return response


def encode_message(doc: dict) -> bytes:
    raw, _ = iso8583.encode(doc, SPEC)
    return bytes(raw)


def decode_message(raw: bytes) -> dict:
    doc, _ = iso8583.decode(raw, SPEC)
    return doc


def mask_pan(pan: str) -> str:
    """Masque le PAN : 6 premiers + 4 derniers chiffres visibles (regle PCI DSS)."""
    if len(pan) < 13:
        return "*" * len(pan)
    return pan[:6] + "*" * (len(pan) - 10) + pan[-4:]
