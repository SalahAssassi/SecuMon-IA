"""Attaque de flood (M1) : envoie N demandes signees le plus vite possible."""
import argparse
import asyncio
import contextlib
import ssl
import struct

from secumon.common.config import load_dotenv
from secumon.gateway.tls import build_client_context
from secumon.hsm.keys import load_master_key, terminal_mac_key
from secumon.iso8583.mac import sign_message, verify_and_decode
from secumon.iso8583.messages import build_auth_request
from secumon.simulator.terminal import certificate_cn


async def run(args) -> None:
    load_dotenv()
    terminal_id = certificate_cn(args.cert)
    ctx = build_client_context(args.ca, args.cert, args.key)
    mac_key = terminal_mac_key(load_master_key(), terminal_id)

    reader, writer = await asyncio.open_connection(
        args.host, args.port, ssl=ctx, server_hostname="localhost"
    )
    sent = approved = 0
    print(f"!!! ATTAQUE FLOOD : {args.count} messages depuis {terminal_id}")
    try:
        for _ in range(args.count):
            request = build_auth_request("4111111111111111", 1000, terminal_id, "MERCHANT0000001")
            raw = sign_message(request, mac_key)
            writer.write(struct.pack(">H", len(raw)) + raw)
            await writer.drain()
            sent += 1
            (n,) = struct.unpack(">H", await reader.readexactly(2))
            if verify_and_decode(await reader.readexactly(n), mac_key).get("39") == "00":
                approved += 1
    except (ssl.SSLError, ConnectionError, asyncio.IncompleteReadError) as exc:
        print(f"Connexion COUPEE par la passerelle au message n°{sent} ({type(exc).__name__})")
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    print(f"Bilan : {sent} envoyes / {args.count} prevus - {approved} approuves")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Simulation d'un flood sur la passerelle")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8583)
    p.add_argument("--ca", default="pki/ca/ca.crt")
    p.add_argument("--cert", default="pki/terminals/TPE-0001.crt")
    p.add_argument("--key", default="pki/terminals/TPE-0001.key")
    p.add_argument("--count", type=int, default=50)
    asyncio.run(run(p.parse_args()))
