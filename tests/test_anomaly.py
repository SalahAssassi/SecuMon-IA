import numpy as np
import pandas as pd
import pytest

from secumon.ml.models import anomaly


def _df(n=500, seed=0):
    """Transactions synthetiques au comportement 'normal'."""
    rng = np.random.default_rng(seed)
    return pd.DataFrame({
        "channel": rng.choice(["swipe", "chip", "online"], n),
        "amount": rng.gamma(2.0, 20.0, n),
        "amt_ratio_avg_90d": rng.normal(1.0, 0.3, n),
        "amt_zscore_90d": rng.normal(0.0, 1.0, n),
        "n_tx_1h": rng.integers(0, 2, n).astype(float),
        "n_tx_24h": rng.integers(0, 4, n).astype(float),
        "amt_sum_24h": rng.gamma(2.0, 40.0, n),
        "n_err_24h": np.zeros(n),
        "secs_since_prev": rng.gamma(2.0, 20000.0, n),
        "dist_home_km": rng.gamma(1.5, 5.0, n),
        "dist_prev_km": rng.gamma(1.5, 5.0, n),
        "speed_kmh": rng.gamma(1.5, 2.0, n),
        "country_new": np.zeros(n),
        "merchant_new": rng.binomial(1, 0.03, n).astype(float),
        "mcc_new": rng.binomial(1, 0.01, n).astype(float),
        "hour": rng.integers(7, 22, n).astype(float),
        "is_fraud": np.zeros(n, dtype=bool),
    })


def test_matrix_uses_neutral_values_and_has_no_nan():
    df = _df(3)
    df.loc[0, "channel"] = "online"
    for c in ["secs_since_prev", "amt_ratio_avg_90d", "amt_zscore_90d",
              "dist_home_km", "dist_prev_km", "speed_kmh", "country_new"]:
        df.loc[0, c] = np.nan
    df.loc[1, "amount"] = -500.0                         # remboursement

    X = anomaly.anomaly_matrix(df)

    assert list(X.columns) == anomaly.ANOMALY_COLUMNS
    assert not X.isna().any().any()
    assert X.loc[0, "online"] == 1.0
    assert X.loc[0, "amt_ratio_avg_90d"] == pytest.approx(np.log1p(1.0))
    assert X.loc[0, "amt_zscore_90d"] == 0.0
    assert X.loc[0, "dist_home_km"] == 0.0
    assert X.loc[0, "secs_since_prev"] == pytest.approx(np.log1p(90 * 24 * 3600.0))
    assert X.loc[1, "amount"] == pytest.approx(-np.log1p(500.0))   # le signe est conserve


def test_label_is_never_used():
    """Changer l'etiquette ne change rien a la matrice du moteur A."""
    df = _df(50)
    autre = df.copy()
    autre["is_fraud"] = True
    X1, X2 = anomaly.anomaly_matrix(df), anomaly.anomaly_matrix(autre)
    assert "is_fraud" not in X1.columns and "is_fraud" not in anomaly.ANOMALY_COLUMNS
    pd.testing.assert_frame_equal(X1, X2)


def test_selected_columns_are_valid_behaviour_columns():
    assert set(anomaly.SELECTED_COLUMNS) <= set(anomaly.ANOMALY_COLUMNS)
    assert "is_fraud" not in anomaly.SELECTED_COLUMNS


def test_isolation_forest_ranks_obvious_outlier_first():
    df = _df(500)
    intrus = pd.DataFrame([{
        "channel": "swipe", "amount": 5000.0, "amt_ratio_avg_90d": 50.0, "amt_zscore_90d": 40.0,
        "n_tx_1h": 8.0, "n_tx_24h": 20.0, "amt_sum_24h": 20000.0, "n_err_24h": 5.0,
        "secs_since_prev": 30.0, "dist_home_km": 9000.0, "dist_prev_km": 9000.0,
        "speed_kmh": 500000.0, "country_new": 1.0, "merchant_new": 1.0, "mcc_new": 1.0,
        "hour": 3.0, "is_fraud": False,
    }])
    df = pd.concat([df, intrus], ignore_index=True)
    X = anomaly.anomaly_matrix(df)

    # max_samples="auto" : le mini-jeu (501 lignes) est plus petit que 4096.
    model = anomaly.fit_isolation_forest(X, max_samples="auto", n_jobs=1)
    scores = anomaly.anomaly_score(model, X)

    assert list(model.feature_names_in_) == list(anomaly.SELECTED_COLUMNS)
    assert int(np.argmax(scores)) == len(df) - 1


def test_fit_rejects_unknown_or_missing_columns():
    X = anomaly.anomaly_matrix(_df(20))
    with pytest.raises(ValueError, match="Colonnes manquantes"):
        anomaly.fit_isolation_forest(X.drop(columns="dist_home_km"), max_samples="auto")
    with pytest.raises(ValueError, match="Colonnes inattendues"):
        anomaly.fit_isolation_forest(X, columns=("is_fraud",), max_samples="auto")
