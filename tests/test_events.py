"""Tests du journal d'evenements : PAN jamais en clair, attaques etiquetees."""
import json

from secumon.gateway.events import EventLog
from secumon.gateway.replay import ReplayGuard
from secumon.gateway.server import process_message
from secumon.gateway.tokenization import PanTokenizer
from secumon.iso8583.mac import sign_message
from secumon.iso8583.messages import build_auth_request

KEY = bytes(range(16))   # cle MAC de TEST
TOKEN_KEY = "00" * 32     # cle de tokenisation de TEST
PAN = "4111111111111111"  # carte de test Visa


class FakeStore:
    def __init__(self):
        self.data = {}

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.data:
            return None
        self.data[key] = value
        return True


def signed_request():
    return sign_message(build_auth_request(PAN, 15000, "TPE-0001", "MERCHANT0000001"), KEY)


def read_events(events):
    return [json.loads(line) for line in events.path.read_text().splitlines()]


def test_transaction_journalisee_avec_token_jamais_le_pan(tmp_path):
    events, tokenizer = EventLog(str(tmp_path / "events.jsonl")), PanTokenizer(TOKEN_KEY)
    process_message(signed_request(), "TPE-0001", KEY, ReplayGuard(FakeStore()), tokenizer, events)

    assert PAN not in events.path.read_text()          # conformite PCI DSS : aucun PAN en clair
    event = read_events(events)[0]
    assert event["type"] == "transaction"
    assert event["token"] == tokenizer.tokenize(PAN)
    assert event["bin"] == "411111"


def test_attaque_journalisee_avec_sa_raison(tmp_path):
    events, guard = EventLog(str(tmp_path / "events.jsonl")), ReplayGuard(FakeStore())
    tokenizer, raw = PanTokenizer(TOKEN_KEY), signed_request()
    process_message(raw, "TPE-0001", KEY, guard, tokenizer, events)
    process_message(raw, "TPE-0001", KEY, guard, tokenizer, events)  # rejeu

    last = read_events(events)[-1]
    assert last["type"] == "security"
    assert last["reason"] == "REPLAY"
    assert PAN not in events.path.read_text()
