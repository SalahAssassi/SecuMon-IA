"""Moteur A : detection d'anomalies non supervisee (Isolation Forest, scikit-learn).

L'etiquette is_fraud n'est jamais utilisee : le modele apprend uniquement le comportement
normal. Seules les features comportementales (ecarts aux habitudes du client) sont utilisees ;
le profil financier est exclu (un client aise n'est pas une anomalie).
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
    """Matrice du moteur A : 16 colonnes numeriques, sans valeur manquante, sans etiquette."""
    X = pd.DataFrame(index=df.index)
    X["online"] = (df["channel"] == "online").astype("float64")
    for c in BEHAVIOUR_FEATURES:
        s = df[c].astype("float64").fillna(NEUTRAL.get(c, 0.0))
        if c in SIGNED_LOG:
            s = np.sign(s) * np.log1p(np.abs(s))
        X[c] = s
    return X


def fit_isolation_forest(X: pd.DataFrame, seed: int = 42, n_estimators: int = 200,
                         n_jobs: int = 4) -> IsolationForest:
    if list(X.columns) != ANOMALY_COLUMNS:
        raise ValueError("Colonnes inattendues : utiliser anomaly_matrix()")
    return IsolationForest(n_estimators=n_estimators, random_state=seed, n_jobs=n_jobs).fit(X)


def anomaly_score(model: IsolationForest, X: pd.DataFrame) -> np.ndarray:
    """Score d'anomalie : plus il est eleve, plus la transaction est inhabituelle."""
    return -model.score_samples(X)
