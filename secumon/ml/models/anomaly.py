"""Moteur A : detection d'anomalies non supervisee (Isolation Forest, scikit-learn).

L'etiquette is_fraud n'est jamais utilisee : le modele apprend uniquement le comportement normal.

Historique (notebook 09, validation uniquement, criteres fixes avant execution) :
- v1 : 16 features comportementales, max_samples 256 -> PR-AUC validation 0,0225 ;
- v2 (retenue) : 8 features de nouveaute et de geographie, max_samples 4096 -> 0,0677 (x 3).
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

BEHAVIOUR_FEATURES = [
    "amount", "amt_ratio_avg_90d", "amt_zscore_90d",
    "n_tx_1h", "n_tx_24h", "amt_sum_24h", "n_err_24h", "secs_since_prev",
    "dist_home_km", "dist_prev_km", "speed_kmh",
    "country_new", "merchant_new", "mcc_new",
    "hour",
]
ANOMALY_COLUMNS = ["online"] + BEHAVIOUR_FEATURES

# Configuration retenue (v2) : nouveaute + geographie.
SELECTED_COLUMNS = ("online", "country_new", "merchant_new", "mcc_new",
                    "dist_home_km", "dist_prev_km", "speed_kmh", "amt_ratio_avg_90d")
DEFAULT_MAX_SAMPLES = 4096

# Transformation log signee pour les variables a queue lourde (ex. vitesse 958 123 km/h).
SIGNED_LOG = ["amount", "amt_ratio_avg_90d", "amt_zscore_90d", "amt_sum_24h",
              "secs_since_prev", "dist_home_km", "dist_prev_km", "speed_kmh"]

# Valeur manquante = "rien d'inhabituel" (pas d'historique, achat en ligne, 1re transaction).
NEUTRAL = {
    "amt_ratio_avg_90d": 1.0,
    "amt_zscore_90d": 0.0,
    "secs_since_prev": 90 * 24 * 3600.0,
    "dist_home_km": 0.0,
    "dist_prev_km": 0.0,
    "speed_kmh": 0.0,
    "country_new": 0.0,
}


def anomaly_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """Matrice complete (16 colonnes numeriques), sans valeur manquante, sans etiquette."""
    X = pd.DataFrame(index=df.index)
    X["online"] = (df["channel"] == "online").astype("float64")
    for c in BEHAVIOUR_FEATURES:
        s = df[c].astype("float64").fillna(NEUTRAL.get(c, 0.0))
        if c in SIGNED_LOG:
            s = np.sign(s) * np.log1p(np.abs(s))
        X[c] = s
    return X


def fit_isolation_forest(X: pd.DataFrame, columns: tuple[str, ...] = SELECTED_COLUMNS,
                         max_samples: int | str = DEFAULT_MAX_SAMPLES, seed: int = 42,
                         n_estimators: int = 200, n_jobs: int = 4) -> IsolationForest:
    unknown = [c for c in columns if c not in ANOMALY_COLUMNS]
    if unknown or not columns:
        raise ValueError(f"Colonnes inattendues : {unknown}")
    missing = [c for c in columns if c not in X.columns]
    if missing:
        raise ValueError(f"Colonnes manquantes : {missing} (utiliser anomaly_matrix())")
    model = IsolationForest(n_estimators=n_estimators, max_samples=max_samples,
                            random_state=seed, n_jobs=n_jobs)
    return model.fit(X[list(columns)])


def anomaly_score(model: IsolationForest, X: pd.DataFrame) -> np.ndarray:
    """Score d'anomalie (plus eleve = plus inhabituel), sur les colonnes apprises par le modele."""
    return -model.score_samples(X[list(model.feature_names_in_)])
