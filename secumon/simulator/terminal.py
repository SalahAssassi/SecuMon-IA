"""Terminal de paiement simule (M1) : demande d'autorisation ISO 8583 signee (MAC DE64)."""
import argparse
import asyncio
import ssl
import struct
from pathlib import Path

import iso8583
from cryptography import x509
from cryptography.x509.oid import NameOID

from secumon.common.config import load_dotenv
from secumon.gateway.tls import build_client_context
from secumon.simulator.keystore import load_terminal_key
from secumon.iso8583.mac import MacError, sign_message, verify_and_decode
from secumon.iso8583.messages import SPEC, build_auth_request, decode_message, encode_message


def certificate_cn(cert_path: str) -> str:
    """Identite reelle du terminal = CN de son certificat."""
    cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def show_response(response_raw: bytes, mac_key: bytes) -> None:
    try:
        response = verify_and_decode(response_raw, mac_key)
        mac_status = "VALIDE"
    except MacError as exc:
        response = decode_message(response_raw)
        mac_status = f"INVALIDE ({exc})"
    print("\n=== Reponse recue ===")
    iso8583.pp(response, SPEC)
    print(f"\nMAC de la reponse : {mac_status}")
    print(f"Resultat : DE39 = {response.get('39')}")


async def run(args) -> None:
    load_dotenv()
    ctx = build_client_context(args.ca, args.cert, args.key)
    mac_key = load_terminal_key(certificate_cn(args.cert))

    request = build_auth_request(
        pan=args.pan,
        amount_cents=round(args.amount * 100),
        terminal_id=args.terminal_id,
        merchant_id=args.merchant,
        mcc=args.mcc,
    )
    raw = encode_message(request) if args.no_mac else sign_message(request, mac_key)

    if args.tamper:
        forged = b"000099999900"  # 999 999,00
        raw = raw.replace(request["4"].encode(), forged, 1)
        print(f"!!! ATTAQUE : montant modifie en transit {request['4']} -> {forged.decode()}")

    print("=== Demande envoyee ===")
    iso8583.pp(decode_message(raw), SPEC)

    attempts = 2 if args.replay else 1
    try:
        reader, writer = await asyncio.open_connection(
            args.host, args.port, ssl=ctx, server_hostname="localhost"
        )
        for attempt in range(1, attempts + 1):
            if args.replay:
                print(f"\n>>> Envoi {attempt}/{attempts} du MEME message (STAN={request['11']})")
            writer.write(struct.pack(">H", len(raw)) + raw)
            await writer.drain()
            (n,) = struct.unpack(">H", await reader.readexactly(2))
            show_response(await reader.readexactly(n), mac_key)
        writer.close()
        await writer.wait_closed()
    except (ssl.SSLError, ConnectionError, asyncio.IncompleteReadError) as exc:
        print(f"\nREFUSE - {type(exc).__name__} : {exc}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="TPE simule SecuMon-IA")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8583)
    p.add_argument("--ca", default="pki/ca/ca.crt")
    p.add_argument("--cert", default="pki/terminals/TPE-0001.crt")
    p.add_argument("--key", default="pki/terminals/TPE-0001.key")
    p.add_argument("--terminal-id", default="TPE-0001", help="valeur placee dans DE41")
    p.add_argument("--pan", default="4111111111111111", help="carte de TEST uniquement")
    p.add_argument("--amount", type=float, default=150.00)
    p.add_argument("--merchant", default="MERCHANT0000001")
    p.add_argument("--mcc", default="5411")
    p.add_argument("--tamper", action="store_true", help="attaque : modifie le montant apres le MAC")
    p.add_argument("--no-mac", action="store_true", help="attaque : envoie le message sans MAC")
    p.add_argument("--replay", action="store_true", help="attaque : renvoie deux fois le meme message")
    asyncio.run(run(p.parse_args()))