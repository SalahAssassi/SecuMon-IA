"""Terminal de paiement simule (M1) : envoie une demande d'autorisation ISO 8583 0100."""
import argparse
import asyncio
import ssl
import struct

import iso8583

from secumon.gateway.tls import build_client_context
from secumon.iso8583.messages import SPEC, build_auth_request, decode_message, encode_message


async def run(args) -> None:
    ctx = build_client_context(args.ca, args.cert, args.key)
    request = build_auth_request(
        pan=args.pan,
        amount_cents=round(args.amount * 100),
        terminal_id=args.terminal_id,
        merchant_id=args.merchant,
        mcc=args.mcc,
    )
    raw = encode_message(request)

    print("=== Demande envoyee ===")
    iso8583.pp(request, SPEC)

    try:
        reader, writer = await asyncio.open_connection(
            args.host, args.port, ssl=ctx, server_hostname="localhost"
        )
        writer.write(struct.pack(">H", len(raw)) + raw)
        await writer.drain()
        (n,) = struct.unpack(">H", await reader.readexactly(2))
        response = decode_message(await reader.readexactly(n))
        writer.close()
        await writer.wait_closed()
    except (ssl.SSLError, ConnectionError, asyncio.IncompleteReadError) as exc:
        print(f"\nREFUSE - {type(exc).__name__} : {exc}")
        return

    print("\n=== Reponse recue ===")
    iso8583.pp(response, SPEC)
    print(f"\nResultat : DE39 = {response.get('39')}")


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
    asyncio.run(run(p.parse_args()))