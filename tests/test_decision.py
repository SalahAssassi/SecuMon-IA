import numpy as np
import pytest
import yaml

from secumon.ml import decision as d

POL = d.DecisionPolicy(decline_b=0.8, review_b=0.5, review_a=0.6)


def test_decide_three_actions_and_codes():
    assert d.decide(0.9, 0.0, POL) == d.DECLINE
    assert d.decide(0.9, 0.99, POL) == d.DECLINE          # le refus est prioritaire
    assert d.decide(0.6, 0.0, POL) == d.REVIEW            # B moyen
    assert d.decide(0.1, 0.7, POL) == d.REVIEW            # A2 en alerte
    assert d.decide(0.1, 0.1, POL) == d.APPROVE
    assert d.RESPONSE_CODES == {d.APPROVE: "00", d.REVIEW: "00", d.DECLINE: "59"}


def test_batch_matches_scalar():
    rng = np.random.default_rng(0)
    b, a = rng.random(1000), rng.random(1000)
    assert list(d.decide_batch(b, a, POL)) == [d.decide(x, y, POL) for x, y in zip(b, a)]


def test_policy_rejects_invalid_thresholds():
    with pytest.raises(ValueError):
        d.DecisionPolicy(decline_b=0.5, review_b=0.8, review_a=0.6)   # revue au-dessus du refus
    with pytest.raises(ValueError):
        d.DecisionPolicy(decline_b=0.8, review_b=float("nan"), review_a=0.6)


def test_calibration_respects_review_budget():
    rng = np.random.default_rng(1)
    n = 200_000
    b, a = rng.random(n), rng.random(n)

    pol = d.calibrate_review_thresholds(b, a, decline_b=0.999, review_rate=0.002, share_b=0.5)
    actions = d.decide_batch(b, a, pol)

    revues = actions == d.REVIEW
    assert revues.sum() == pytest.approx(0.002 * n, rel=0.05)                     # budget total
    assert (revues & (b >= pol.review_b)).sum() == pytest.approx(0.001 * n, rel=0.1)  # moitie via B
    assert pol.decline_b == 0.999


def test_policy_yaml_roundtrip(tmp_path):
    path = tmp_path / "decision.yaml"
    d.save_policy(POL, path, meta={"review_rate": 0.002})
    assert d.load_policy(path) == POL


def test_load_policy_rejects_incomplete_or_malicious_yaml(tmp_path):
    incomplet = tmp_path / "incomplet.yaml"
    incomplet.write_text("decision:\n  decline_b: 0.8\n")
    with pytest.raises(ValueError, match="invalide"):
        d.load_policy(incomplet)

    # YAML piege : avec yaml.load non securise, ceci executerait une commande systeme.
    piege = tmp_path / "piege.yaml"
    piege.write_text("decision: !!python/object/apply:os.system ['echo pirate']\n")
    with pytest.raises(yaml.YAMLError):
        d.load_policy(piege)
