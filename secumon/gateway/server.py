"""Passerelle acquereur SecuMon-IA (M2) - canal mTLS + traitement ISO 8583."""
import asyncio
import contextlib
import logging
import ssl
import struct

import iso8583

from secumon.gateway.tls import build_server_context, peer_common_name
from secumon.iso8583.messages import (
    MTI_AUTH_REQUEST, RC_APPROVED, RC_FORMAT_ERROR, RC_SECURITY_VIOLATION,
    build_auth_response, decode_message, encode_message, mask_pan,
)

HOST, PORT = "127.0.0.1", 8583
CERT, KEY, CA = "pki/gateway/gateway.crt", "pki/gateway/gateway.key", "pki/ca/ca.crt"
MAX_MESSAGE = 4096

log = logging.getLogger("secumon.gateway")


async def read_frame(reader: asyncio.StreamReader) -> bytes:
    (length,) = struct.unpack(">H", await reader.readexactly(2))
    if length == 0 or length > MAX_MESSAGE:
        raise ValueError(f"longueur de message invalide : {length}")
    return await reader.readexactly(length)


def write_frame(writer: asyncio.StreamWriter, payload: bytes) -> None:
    writer.write(struct.pack(">H", len(payload)) + payload)


def process_message(raw: bytes, terminal_id: str) -> bytes:
    """Decode, valide et repond a un message ISO 8583. Fonction pure : facile a tester."""
    try:
        request = decode_message(raw)
    except iso8583.DecodeError as exc:
        log.warning("[%s] message ISO 8583 MALFORME rejete : %s", terminal_id, exc)
        return encode_message({"t": "0110", "39": RC_FORMAT_ERROR})

    if request.get("t") != MTI_AUTH_REQUEST:
        log.warning("[%s] MTI non supporte : %s", terminal_id, request.get("t"))
        return encode_message(build_auth_response(request, RC_FORMAT_ERROR))

    declared_terminal = request.get("41", "").strip()
    if declared_terminal != terminal_id:
        log.warning("[%s] USURPATION : le certificat est %s mais DE41 annonce %s",
                    terminal_id, terminal_id, declared_terminal)
        return encode_message(build_auth_response(request, RC_SECURITY_VIOLATION))

    amount = int(request.get("4", "0")) / 100
    log.info("[%s] %s STAN=%s PAN=%s montant=%.2f devise=%s MCC=%s -> DE39=%s",
             terminal_id, request["t"], request.get("11"), mask_pan(request.get("2", "")),
             amount, request.get("49"), request.get("18"), RC_APPROVED)
    return encode_message(build_auth_response(request, RC_APPROVED))


async def handle_connection(reader, writer, tls_ctx: ssl.SSLContext) -> None:
    peer = writer.get_extra_info("peername")
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

    try:
        while True:
            raw = await read_frame(reader)
            write_frame(writer, process_message(raw, terminal_id))
            await writer.drain()
    except asyncio.IncompleteReadError:
        log.info("[%s] deconnexion", terminal_id)
    except ValueError as exc:
        log.warning("[%s] trame rejetee : %s", terminal_id, exc)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def main() -> None:
    tls_ctx = build_server_context(CERT, KEY, CA)
    server = await asyncio.start_server(
        lambda r, w: handle_connection(r, w, tls_ctx), HOST, PORT
    )
    log.info("Passerelle SecuMon-IA en ecoute sur %s:%d (TLS 1.3 + mTLS + ISO 8583)", HOST, PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s - %(message)s")
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main())
