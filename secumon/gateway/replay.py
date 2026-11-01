"""Anti-rejeu (M2) : fraicheur de DE7 + unicite (terminal, STAN, DE7) dans Redis."""
from datetime import datetime, timedelta, timezone

RC_DUPLICATE = "94"            # transmission en double (code ISO 8583)
RC_SECURITY_VIOLATION = "63"


class ReplayError(Exception):
    """Message rejoue, perime ou date invalide."""

    def __init__(self, message: str, response_code: str):
        super().__init__(message)
        self.response_code = response_code


def parse_de7(de7: str, now: datetime) -> datetime:
    """DE7 = MMJJhhmmss (UTC) sans annee : on retient l'annee la plus proche de 'now'."""
    sent_at = datetime.strptime(f"{now.year}{de7}", "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    if sent_at - now > timedelta(days=180):
        sent_at = sent_at.replace(year=now.year - 1)
    elif now - sent_at > timedelta(days=180):
        sent_at = sent_at.replace(year=now.year + 1)
    return sent_at


class ReplayGuard:
    """Detecte les rejeux. 'store' = client Redis (ou un faux store pour les tests)."""

    def __init__(self, store, window_seconds: int = 300, max_skew_seconds: int = 120):
        self.store = store
        self.window = window_seconds
        self.max_skew = max_skew_seconds

    def check(self, terminal_id: str, stan: str, de7: str, now: datetime | None = None) -> None:
        now = now or datetime.now(timezone.utc)

        try:
            sent_at = parse_de7(de7, now)
        except (TypeError, ValueError):
            raise ReplayError(f"DE7 invalide : {de7!r}", RC_SECURITY_VIOLATION) from None
        skew = abs((now - sent_at).total_seconds())
        if skew > self.max_skew:
            raise ReplayError(f"message perime ou horloge incoherente (ecart {skew:.0f} s)",
                              RC_SECURITY_VIOLATION)

        key = f"secumon:replay:{terminal_id}:{stan}:{de7}"
        if not self.store.set(key, "1", nx=True, ex=self.window):
            raise ReplayError(f"REJEU detecte (STAN={stan}, DE7={de7})", RC_DUPLICATE)
