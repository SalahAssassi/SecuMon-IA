"""Moteur de decision : transforme les scores des moteurs B (supervise) et A2 (anomalies)
en action, au moment de l'autorisation.

    SI score_B >= decline_b                         -> DECLINE (DE39 = 59)
    SINON SI score_B >= review_b OU score_A >= review_a -> REVIEW  (DE39 = 00 + alerte analyste)
    SINON                                           -> APPROVE (DE39 = 00)

Les seuils portent uniquement sur des scores de modeles (aucune regle sur le pays, le montant...).
Ce sont des parametres de politique metier, ranges dans config/decision.yaml.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import yaml

APPROVE, REVIEW, DECLINE = "APPROVE", "REVIEW", "DECLINE"
RESPONSE_CODES = {APPROVE: "00", REVIEW: "00", DECLINE: "59"}
POLICY_KEYS = ("decline_b", "review_b", "review_a")


@dataclass(frozen=True)
class DecisionPolicy:
    decline_b: float
    review_b: float
    review_a: float

    def __post_init__(self) -> None:
        for k in POLICY_KEYS:
            v = getattr(self, k)
            if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
                raise ValueError(f"{k} doit etre un nombre fini")
        if not 0.0 <= self.review_b <= self.decline_b <= 1.0:
            raise ValueError("Il faut 0 <= review_b <= decline_b <= 1")


def decide(score_b: float, score_a: float, policy: DecisionPolicy) -> str:
    """Decision pour une transaction (chemin temps reel)."""
    if score_b >= policy.decline_b:
        return DECLINE
    if score_b >= policy.review_b or score_a >= policy.review_a:
        return REVIEW
    return APPROVE


def decide_batch(score_b, score_a, policy: DecisionPolicy) -> np.ndarray:
    """Meme decision, vectorisee (evaluation hors ligne)."""
    b = np.asarray(score_b, dtype=float)
    a = np.asarray(score_a, dtype=float)
    return np.select([b >= policy.decline_b, (b >= policy.review_b) | (a >= policy.review_a)],
                     [DECLINE, REVIEW], default=APPROVE)


def calibrate_review_thresholds(score_b, score_a, decline_b: float, review_rate: float,
                                share_b: float = 0.5) -> DecisionPolicy:
    """Seuils de revue tels que REVIEW represente `review_rate` des transactions,
    dont la part `share_b` via le moteur B et le reste via le moteur A2."""
    if not 0.0 < review_rate < 1.0 or not 0.0 <= share_b <= 1.0:
        raise ValueError("review_rate doit etre dans ]0, 1[ et share_b dans [0, 1]")
    b = np.asarray(score_b, dtype=float)
    a = np.asarray(score_a, dtype=float)
    budget = review_rate * len(b)

    non_refusees = b < decline_b
    k_b = share_b * budget
    if k_b > 0:
        review_b = float(np.quantile(b[non_refusees], 1 - k_b / non_refusees.sum()))
    else:
        review_b = float(decline_b)

    reste = non_refusees & (b < review_b)
    k_a = budget - k_b
    if k_a > 0:
        review_a = float(np.quantile(a[reste], 1 - k_a / reste.sum()))
    else:
        review_a = float(a.max()) + 1.0
    return DecisionPolicy(decline_b=float(decline_b), review_b=review_b, review_a=review_a)


def load_policy(path: str | Path) -> DecisionPolicy:
    """Lit la politique. safe_load : un YAML piege ne peut pas executer de code."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    section = data.get("decision")
    if not isinstance(section, dict) or set(section) != set(POLICY_KEYS):
        raise ValueError(f"Section 'decision' invalide : cles attendues {POLICY_KEYS}")
    return DecisionPolicy(**{k: float(section[k]) for k in POLICY_KEYS})


def save_policy(policy: DecisionPolicy, path: str | Path, meta: dict | None = None) -> None:
    content = {"decision": {k: float(getattr(policy, k)) for k in POLICY_KEYS}}
    if meta:
        content["decision_meta"] = meta
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(yaml.safe_dump(content, sort_keys=False, allow_unicode=True),
                          encoding="utf-8")
