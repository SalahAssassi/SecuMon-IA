"""Passerelle acquereur SecuMon-IA (M2) - mTLS + ISO 8583 + MAC + anti-rejeu + rate limiting."""
import asyncio
import contextlib
import logging
import os
import ssl
import struct

import iso8583
import redis

from secumon.common.config import load_dotenv
from secumon.gateway.ratelimit import RateLimiter
from secumon.gateway.replay import ReplayError, ReplayGuard
from secumon.gateway.tls import build_server_context, peer_common_name
from secumon.hsm.keys import load_master_key, terminal_mac_key
from secumon.iso8583.mac import MacError, sign_message, verify_and_decode
from secumon.iso8583.messages import (
    MTI_AUTH_REQUEST, MTI_AUTH_RESPONSE, RC_APPROVED, RC_FORMAT_ERROR,
    RC_SECURITY_VIOLATION, build_auth_response, mask_pan,
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


def process_message(raw: bytes, terminal_id: str, mac_key: bytes, guard: ReplayGuard) -> bytes:
    """Chaine de controles : syntaxe -> MAC -> MTI -> identite -> anti-rejeu -> decision."""
    # 1. Syntaxe + integrite (MAC)
    try:
        request = verify_and_decode(raw, mac_key)
    except iso8583.DecodeError as exc:
        log.warning("[%s] message ISO 8583 MALFORME rejete : %s", terminal_id, exc)
        return sign_message({"t": MTI_AUTH_RESPONSE, "39": RC_FORMAT_ERROR}, mac_key)
    except MacError as exc:
        log.warning("[%s] INTEGRITE : %s", terminal_id, exc)
        return sign_message({"t": MTI_AUTH_RESPONSE, "39": RC_SECURITY_VIOLATION}, mac_key)

    # 2. Type de message
    if request.get("t") != MTI_AUTH_REQUEST:
        log.warning("[%s] MTI non supporte : %s", terminal_id, request.get("t"))
        return sign_message(build_auth_response(request, RC_FORMAT_ERROR), mac_key)

    # 3. Liaison certificat <-> DE41
    declared_terminal = request.get("41", "").strip()
    if declared_terminal != terminal_id:
        log.warning("[%s] USURPATION : le certificat est %s mais DE41 annonce %s",
                    terminal_id, terminal_id, declared_terminal)
        return sign_message(build_auth_response(request, RC_SECURITY_VIOLATION), mac_key)

    # 4. Anti-rejeu (uniquement sur des messages authentifies)
    try:
        guard.check(terminal_id, request.get("11"), request.get("7"))
    except ReplayError as exc:
        log.warning("[%s] ANTI-REJEU : %s", terminal_id, exc)
        return sign_message(build_auth_response(request, exc.response_code), mac_key)

    # 5. Transaction acceptee (le scoring de fraude M5 viendra ici)
    amount = int(request.get("4", "0")) / 100
    log.info("[%s] %s STAN=%s PAN=%s montant=%.2f devise=%s MCC=%s MAC=OK -> DE39=%s",
             terminal_id, request["t"], request.get("11"), mask_pan(request.get("2", "")),
             amount, request.get("49"), request.get("18"), RC_APPROVED)
    return sign_message(build_auth_response(request, RC_APPROVED), mac_key)


async def handle_connection(reader, writer, tls_ctx: ssl.SSLContext, master_key: bytes,
                            guard: ReplayGuard, limiter: RateLimiter) -> None:
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
    mac_key = terminal_mac_key(master_key, terminal_id)  # d'apres le CERTIFICAT, jamais DE41
    log.info("Connexion ACCEPTEE : terminal=%s ip=%s %s %s",
             terminal_id, peer, ssl_obj.version(), ssl_obj.cipher()[0])

    try:
        while True:
            raw = await read_frame(reader)
            # Rate limiting AVANT tout traitement couteux (MAC, Redis anti-rejeu...)
            if not limiter.allow(terminal_id):
                log.warning("[%s] RATE LIMIT : plus de %d messages/s -> connexion coupee "
                            "(flood suspect)", terminal_id, limiter.max_per_second)
                break
            write_frame(writer, process_message(raw, terminal_id, mac_key, guard))
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
    load_dotenv()
    master_key = load_master_key()

    store = redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0"),
                                 decode_responses=True)
    try:
        store.ping()
    except redis.ConnectionError:
        log.error("Redis injoignable : lancez 'sudo service redis-server start'")
        return
    guard = ReplayGuard(store)
    limiter = RateLimiter(store, int(os.environ.get("RATE_LIMIT_PER_SECOND", "10")))

    tls_ctx = build_server_context(CERT, KEY, CA)
    server = await asyncio.start_server(
        lambda r, w: handle_connection(r, w, tls_ctx, master_key, guard, limiter), HOST, PORT
    )
    log.info("Passerelle SecuMon-IA en ecoute sur %s:%d "
             "(TLS 1.3 + mTLS + ISO 8583 + MAC + anti-rejeu + rate limiting %d/s)",
             HOST, PORT, limiter.max_per_second)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s - %(message)s")
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main())