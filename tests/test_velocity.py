import duckdb
import pandas as pd
import pytest

from secumon.ml.features import velocity


def _tx():
    # Carte A : deux transactions dans la meme minute (10:00), puis 10:30, 11:00, lendemain.
    # Carte B : une transaction qui ne doit jamais etre comptee pour la carte A.
    return pd.DataFrame({
        "tx_id": [0, 1, 2, 3, 4, 5],
        "card_id": ["A", "A", "A", "A", "A", "B"],
        "ts": pd.to_datetime([
            "2014-01-01 10:00", "2014-01-01 10:00", "2014-01-01 10:30",
            "2014-01-01 11:00", "2014-01-02 12:00", "2014-01-01 10:15",
        ]).astype("datetime64[us]"),
        "amount": [10.0, 20.0, 30.0, -5.0, 40.0, 99.0],
        "errors": [None, None, "Bad PIN", None, None, None],
    })


def _features(tmp_path, tx, name):
    src = tmp_path / f"{name}_tx.parquet"
    tx.to_parquet(src, index=False)
    out = tmp_path / f"{name}_velocity.parquet"
    assert velocity.build_velocity(duckdb.connect(), src, out) == len(tx)
    return pd.read_parquet(out).set_index("tx_id").sort_index()


def test_velocity_values(tmp_path):
    f = _features(tmp_path, _tx(), "v")
    # 1re transaction de la carte : rien dans le passe.
    assert f.loc[0, ["n_tx_1h", "n_tx_24h", "n_tx_7d", "n_err_24h"]].tolist() == [0, 0, 0, 0]
    assert pd.isna(f.loc[0, "secs_since_prev"])
    # Meme minute : tx 1 voit tx 0 (et tx 0 ne voit pas tx 1, ligne precedente).
    assert f.loc[1, "n_tx_1h"] == 1
    assert f.loc[1, "amt_sum_1h"] == pytest.approx(10.0)
    assert f.loc[1, "secs_since_prev"] == pytest.approx(0.0)
    # 10:30 : voit 0 et 1 ; sa propre erreur n'est pas comptee.
    assert f.loc[2, "n_tx_1h"] == 2
    assert f.loc[2, "amt_sum_1h"] == pytest.approx(30.0)
    assert f.loc[2, "n_err_24h"] == 0
    assert f.loc[2, "secs_since_prev"] == pytest.approx(1800.0)
    # 11:00 : voit 0, 1, 2 (dont l'erreur de tx 2).
    assert f.loc[3, "n_tx_1h"] == 3
    assert f.loc[3, "amt_sum_1h"] == pytest.approx(60.0)
    assert f.loc[3, "n_err_24h"] == 1
    # Lendemain 12:00 : 25 h apres tx 3 -> rien dans les 24 h, 4 transactions sur 7 jours.
    assert f.loc[4, ["n_tx_1h", "n_tx_24h", "n_tx_7d"]].tolist() == [0, 0, 4]
    assert f.loc[4, "amt_sum_24h"] == pytest.approx(0.0)
    assert f.loc[4, "secs_since_prev"] == pytest.approx(25 * 3600.0)
    # Carte B isolee de la carte A.
    assert f.loc[5, ["n_tx_1h", "n_tx_24h", "n_tx_7d"]].tolist() == [0, 0, 0]


def test_no_future_leakage(tmp_path):
    """Modifier ou ajouter des transactions FUTURES ne change pas les features du passe."""
    base = _features(tmp_path, _tx(), "base")

    futur = _tx()
    futur.loc[futur["tx_id"] == 4, ["amount", "errors"]] = [9999.0, "Bad CVV"]
    ajout = pd.DataFrame({
        "tx_id": [6, 7],
        "card_id": ["A", "A"],
        # tx 6 : meme minute que tx 3 mais apres elle (tx_id plus grand) -> invisible pour tx 3.
        "ts": pd.to_datetime(["2014-01-01 11:00", "2014-01-05 09:00"]).astype("datetime64[us]"),
        "amount": [500.0, 700.0],
        "errors": ["Bad CVV", None],
    })
    modifie = _features(tmp_path, pd.concat([futur, ajout], ignore_index=True), "futur")

    pd.testing.assert_frame_equal(base.loc[[0, 1, 2, 3, 5]], modifie.loc[[0, 1, 2, 3, 5]])
