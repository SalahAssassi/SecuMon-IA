"""Contextes TLS 1.3 / mTLS de SecuMon-IA."""
import ssl


def build_server_context(cert: str, key: str, ca: str) -> ssl.SSLContext:
    """Contexte serveur : TLS 1.3 uniquement + certificat client OBLIGATOIRE et VERIFIE."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    ctx.load_verify_locations(cafile=ca)      # seule CA de confiance : SecuMon-IA Root CA
    ctx.verify_mode = ssl.CERT_REQUIRED       # exige ET verifie le certificat (= le "m" de mTLS)
    return ctx


def build_client_context(ca: str, cert: str | None = None, key: str | None = None) -> ssl.SSLContext:
    """Contexte client (terminal) : verifie le serveur, presente son certificat s'il en a un."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # verifie le serveur + son nom par defaut
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=ca)
    if cert and key:
        ctx.load_cert_chain(certfile=cert, keyfile=key)
    return ctx


def peer_common_name(ssl_object) -> str | None:
    """Extrait le CN (identifiant du terminal) du certificat presente par le pair."""
    cert = ssl_object.getpeercert() or {}
    for rdn in cert.get("subject", ()):
        for field, value in rdn:
            if field == "commonName":
                return value
    return None
