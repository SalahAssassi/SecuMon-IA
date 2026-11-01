"""Terminal de test (M1) : se connecte a la passerelle en mTLS et envoie un message."""
import argparse
import asyncio
import ssl
import struct

from secumon.gateway.tls import build_client_context


async def run(args) -> None:
    ctx = build_client_context(args.ca, args.cert, args.key)
    try:
        reader, writer = await asyncio.open_connection(
            args.host, args.port, ssl=ctx, server_hostname="localhost"
        )
        payload = args.message.encode()
        writer.write(struct.pack(">H", len(payload)) + payload)
        await writer.drain()
        (n,) = struct.unpack(">H", await reader.readexactly(2))
        reply = await reader.readexactly(n)
        print(f"ACCEPTE - reponse de la passerelle : {reply.decode()}")
        writer.close()
        await writer.wait_closed()
    except (ssl.SSLError, ConnectionError, asyncio.IncompleteReadError) as exc:
        print(f"REFUSE  - {type(exc).__name__} : {exc}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Terminal de test SecuMon-IA")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8583)
    p.add_argument("--ca", default="pki/ca/ca.crt")
    p.add_argument("--cert")
    p.add_argument("--key")
    p.add_argument("--message", default="Bonjour passerelle")
    asyncio.run(run(p.parse_args()))
