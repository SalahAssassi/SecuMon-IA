"""Tests de la limitation de debit."""
from secumon.gateway.ratelimit import RateLimiter


class FakeCounterStore:
    """Imite redis.incr / redis.expire en memoire."""

    def __init__(self):
        self.data = {}

    def incr(self, key):
        self.data[key] = self.data.get(key, 0) + 1
        return self.data[key]

    def expire(self, key, seconds):
        return True


def test_sous_la_limite_accepte():
    limiter = RateLimiter(FakeCounterStore(), max_per_second=3)
    assert all(limiter.allow("TPE-0001", now=1000.0) for _ in range(3))


def test_au_dela_de_la_limite_refuse():
    limiter = RateLimiter(FakeCounterStore(), max_per_second=3)
    for _ in range(3):
        limiter.allow("TPE-0001", now=1000.0)
    assert limiter.allow("TPE-0001", now=1000.0) is False


def test_compteur_independant_par_terminal():
    limiter = RateLimiter(FakeCounterStore(), max_per_second=3)
    for _ in range(4):
        limiter.allow("TPE-0001", now=1000.0)
    assert limiter.allow("TPE-0002", now=1000.0) is True


def test_nouvelle_seconde_remet_a_zero():
    limiter = RateLimiter(FakeCounterStore(), max_per_second=3)
    for _ in range(4):
        limiter.allow("TPE-0001", now=1000.0)
    assert limiter.allow("TPE-0001", now=1001.0) is True
