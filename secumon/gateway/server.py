"""Passerelle acquereur SecuMon-IA (M2) - etape 1 : canal mTLS."""
import asyncio
import contextlib
import logging
import ssl
import struct

from secumon.gateway.tls import build_server_context, peer_common_name

HOST, PORT = "127.0.0.1", 8583
CERT, KEY, CA = "pki/gateway/gateway.crt", "pki/gateway/gateway.key", "pki/ca/ca.crt"
MAX_MESSAGE = 4096  # taille max d'un message : protection contre les messages geants

log = logging.getLogger("secumon.gateway")


async def read_frame(reader: asyncio.StreamReader) -> bytes:
    """Lit un message precede de sa longueur sur 2 octets (big-endian)."""
    (length,) = struct.unpack(">H", await reader.readexactly(2))
    if length == 0 or length > MAX_MESSAGE:
        raise ValueError(f"longueur de message invalide : {length}")
    return await reader.readexactly(length)


def write_frame(writer: asyncio.StreamWriter, payload: bytes) -> None:
    writer.write(struct.pack(">H", len(payload)) + payload)


async def handle_connection(reader, writer, tls_ctx: ssl.SSLContext) -> None:
    peer = writer.get_extra_info("peername")

    # 1. Poignee de main mTLS : tout echec est journalise puis la connexion est coupee
    try:
        await writer.start_tls(tls_ctx)
    except (ssl.SSLError, ConnectionError, OSError) as exc:
        log.warning("REFUS mTLS depuis %s : %s", peer, getattr(exc, "reason", None) or exc)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return

    ssl_obj = writer.get_extra_info("ssl_object")
    terminal_id = peer_common_name(ssl_obj)
    log.info("Connexion ACCEPTEE : terminal=%s ip=%s %s %s",
             terminal_id, peer, ssl_obj.version(), ssl_obj.cipher()[0])

    # 2. Echange de messages
    try:
        while True:
            data = await read_frame(reader)
            log.info("[%s] message recu (%d octets)", terminal_id, len(data))
            write_frame(writer, b"ACK:" + data)
            await writer.drain()
    except asyncio.IncompleteReadError:
        log.info("[%s] deconnexion", terminal_id)
    except ValueError as exc:
        log.warning("[%s] message rejete : %s", terminal_id, exc)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def main() -> None:
    tls_ctx = build_server_context(CERT, KEY, CA)
    server = await asyncio.start_server(
        lambda r, w: handle_connection(r, w, tls_ctx), HOST, PORT
    )
    log.info("Passerelle SecuMon-IA en ecoute sur %s:%d (TLS 1.3 + mTLS)", HOST, PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s - %(message)s")
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main())
