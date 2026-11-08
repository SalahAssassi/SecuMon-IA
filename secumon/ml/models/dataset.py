"""Chargement des jeux pour le moteur B (classification supervisee).

Train : toutes les fraudes + 1 transaction legitime sur `sample_every` (selection
deterministe par tx_id), avec un poids `sample_every` pour compenser l'echantillonnage.
Validation et tests : complets, poids 1, pour mesurer les vraies performances.
"""

from __future__ import annotations

from pathlib import Path

import duckdb
import pandas as pd

from secumon.ml.data.ibm import _sql_path
from secumon.ml.features import gold

SPLITS = ("train", "validation", "test_a", "test_b")
LEGIT_SAMPLE_EVERY = 20
WEIGHT = "sample_weight"


def _select_list() -> str:
    cols = gold.ID_COLUMNS + [gold.LABEL] + gold.SEGMENT_COLUMNS
    cols += [f"CAST({c} AS DOUBLE) AS {c}" for c in gold.NUMERIC_FEATURES]
    cols += [f"CAST({c} AS VARCHAR) AS {c}" for c in gold.CATEGORICAL_FEATURES]
    return ",\n    ".join(cols)


def load_split(con: duckdb.DuckDBPyConnection, gold_path: str | Path, split: str,
               sample_every: int | None = None) -> pd.DataFrame:
    """Charge un jeu de la table gold ; sample_every n'est utilise que pour le train."""
    if split not in SPLITS:
        raise ValueError(f"Jeu inconnu : {split!r} (attendu : {SPLITS})")
    if sample_every is not None and (isinstance(sample_every, bool)
                                     or not isinstance(sample_every, int) or sample_every < 1):
        raise ValueError("sample_every doit etre un entier >= 1")
    src = _sql_path(gold_path)
    where = f"split = '{split}'"
    weight = "1.0"
    if sample_every:
        where += f" AND (is_fraud OR tx_id % {sample_every} = 0)"
        weight = f"CASE WHEN is_fraud THEN 1.0 ELSE {float(sample_every)} END"
    # split verifie par liste blanche, sample_every entier, chemin valide par _sql_path.
    sql = f"SELECT {_select_list()},\n    {weight} AS {WEIGHT}\nFROM read_parquet('{src}')\nWHERE {where}"  # nosec B608
    return con.sql(sql).df()


def make_categories(train: pd.DataFrame) -> dict[str, list[str]]:
    """Categories connues, apprises sur le train uniquement."""
    return {c: sorted(train[c].dropna().unique().tolist()) for c in gold.CATEGORICAL_FEATURES}


def features_frame(df: pd.DataFrame, categories: dict[str, list[str]]) -> pd.DataFrame:
    """Matrice X pour LightGBM : 32 features, categories fixees par le train (inconnue -> NaN)."""
    X = df[gold.FEATURE_COLUMNS].copy()
    for c in gold.CATEGORICAL_FEATURES:
        known = X[c].where(X[c].isin(categories[c]))  # valeur inconnue -> NaN, explicitement
        X[c] = pd.Categorical(known, categories=categories[c])
    return X


def iter_split(con: duckdb.DuckDBPyConnection, gold_path: str | Path, split: str,
               n_parts: int):
    """Lit un jeu complet par morceaux de clients (user_id % n_parts), pour limiter la memoire."""
    if split not in SPLITS:
        raise ValueError(f"Jeu inconnu : {split!r} (attendu : {SPLITS})")
    if isinstance(n_parts, bool) or not isinstance(n_parts, int) or n_parts < 1:
        raise ValueError("n_parts doit etre un entier >= 1")
    src = _sql_path(gold_path)
    for k in range(n_parts):
        # split verifie par liste blanche, n_parts et k entiers, chemin valide par _sql_path.
        sql = f"SELECT {_select_list()},\n    1.0 AS {WEIGHT}\nFROM read_parquet('{src}')\nWHERE split = '{split}' AND user_id % {n_parts} = {k}"  # nosec B608
        yield con.sql(sql).df()
