"""Limitation de debit (M2) : messages max par seconde et par terminal (compteur Redis)."""
import time


class RateLimiter:
    """Fenetre fixe d'une seconde. 'store' = client Redis (ou un faux store pour les tests)."""

    def __init__(self, store, max_per_second: int = 10):
        self.store = store
        self.max_per_second = max_per_second

    def allow(self, terminal_id: str, now: float | None = None) -> bool:
        second = int(now if now is not None else time.time())
        key = f"secumon:rate:{terminal_id}:{second}"
        count = self.store.incr(key)
        if count == 1:
            self.store.expire(key, 2)  # le compteur disparait tout seul
        return count <= self.max_per_second
