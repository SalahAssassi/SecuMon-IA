import duckdb
import pandas as pd
import pytest

from secumon.ml.features import gold
from secumon.ml.models import dataset


def _gold(tmp_path):
    """Mini table gold : 40 transactions legitimes (tx 0-39) + 2 fraudes (tx 41, 43)."""
    tx_ids = list(range(40)) + [41, 43]
    n = len(tx_ids)
    data = {
        "tx_id": tx_ids, "user_id": [1] * n, "card_id": ["U0001-C0"] * n,
        "ts": pd.to_datetime(["2014-01-01"] * n).astype("datetime64[us]"),
        "split": ["train"] * n, "is_fraud": [False] * 40 + [True, True],
        "merchant_country": ["United States"] * n, "is_online": [False] * n,
    }
    for c in gold.NUMERIC_FEATURES:
        data[c] = [1.0] * n
    data["country_new"] = [True] * (n - 1) + [None]
    for c in gold.CATEGORICAL_FEATURES:
        data[c] = ["a"] * n
    data["mcc"] = [5411] * (n - 1) + [9999]
    path = tmp_path / "gold.parquet"
    pd.DataFrame(data).to_parquet(path, index=False)
    return path


def test_train_sampling_keeps_all_frauds_and_weights_legit(tmp_path):
    df = dataset.load_split(duckdb.connect(), _gold(tmp_path), "train", sample_every=20)
    assert sorted(df["tx_id"]) == [0, 20, 41, 43]
    w = df.set_index("tx_id")[dataset.WEIGHT]
    assert w[0] == 20.0 and w[20] == 20.0
    assert w[41] == 1.0 and w[43] == 1.0


def test_full_split_has_unit_weights(tmp_path):
    df = dataset.load_split(duckdb.connect(), _gold(tmp_path), "train")
    assert len(df) == 42
    assert (df[dataset.WEIGHT] == 1.0).all()


def test_unknown_split_is_rejected(tmp_path):
    """Liste blanche : une tentative d'injection SQL dans le nom du jeu est refusee."""
    with pytest.raises(ValueError, match="Jeu inconnu"):
        dataset.load_split(duckdb.connect(), _gold(tmp_path), "train' OR 1=1 --")
    with pytest.raises(ValueError, match="entier"):
        dataset.load_split(duckdb.connect(), _gold(tmp_path), "train", sample_every="20; DROP")


def test_features_frame_types_and_unknown_category(tmp_path):
    train = dataset.load_split(duckdb.connect(), _gold(tmp_path), "train")
    cats = dataset.make_categories(train)
    assert cats["mcc"] == ["5411", "9999"]

    autre = train.copy()
    autre.loc[0, "mcc"] = "1234"                       # MCC jamais vu dans le train
    X = dataset.features_frame(autre, cats)

    assert list(X.columns) == gold.FEATURE_COLUMNS
    assert pd.isna(X.loc[0, "mcc"])
    assert str(X["mcc"].dtype) == "category"
    assert X["amount"].dtype == "float64"
    assert X["country_new"].isna().sum() == 1          # booleen manquant conserve (pas un 0)


def test_iter_split_parts_rebuild_the_full_split(tmp_path):
    path = _gold(tmp_path)
    df = pd.read_parquet(path)
    df["user_id"] = df["tx_id"] % 7                    # plusieurs clients
    df.to_parquet(path, index=False)

    parts = list(dataset.iter_split(duckdb.connect(), path, "train", 3))

    assert len(parts) == 3
    tx = [t for p in parts for t in p["tx_id"]]
    assert sorted(tx) == sorted(df["tx_id"])           # rien de perdu, rien en double
    for k, p in enumerate(parts):
        assert (p["user_id"] % 3 == k).all()           # un client dans un seul morceau
    with pytest.raises(ValueError, match="n_parts"):
        list(dataset.iter_split(duckdb.connect(), path, "train", 0))


def test_load_sample_is_not_enriched_with_frauds(tmp_path):
    """Moteur A : les fraudes (tx 41 et 43) ne sont PAS ajoutees d'office, contrairement au train B."""
    df = dataset.load_sample(duckdb.connect(), _gold(tmp_path), "train", every=20)
    assert sorted(df["tx_id"]) == [0, 20]
    assert not df["is_fraud"].any()
    assert (df[dataset.WEIGHT] == 1.0).all()
