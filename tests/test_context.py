import math

import duckdb
import pandas as pd
import pytest

from secumon.ml.features import context

NY = (40.7128, -74.0060)
ROME = (41.9028, 12.4964)


def haversine_py(lat1, lon1, lat2, lon2):
    """Reference Python independante de la macro SQL."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * 6371.0088 * math.asin(math.sqrt(a))


def _data():
    # Un client (domicile New York), deux cartes. tx 2 est en ligne.
    tx = pd.DataFrame({
        "tx_id": [0, 1, 2, 3],
        "user_id": [7, 7, 7, 7],
        "card_id": ["A", "A", "A", "B"],
        "ts": pd.to_datetime(["2014-01-01 10:00", "2014-01-01 11:00",
                              "2014-01-01 12:00", "2014-01-02 10:00"]).astype("datetime64[us]"),
        "amount": [50.0, 500.0, 20.0, 60.0],
        "mcc": [5411, 5732, 5732, 5411],
        "merchant_id": ["m1", "m2", "m3", "m1"],
        "merchant_country": ["United States", "Italy", None, "United States"],
        "is_online": [False, False, True, False],
    })
    geo = pd.DataFrame({
        "tx_id": [0, 1, 2, 3],
        "merchant_lat": [NY[0], ROME[0], None, NY[0]],
        "merchant_lon": [NY[1], ROME[1], None, NY[1]],
        "geo_precision": ["zip", "city", "online", "zip"],
    })
    customers = pd.DataFrame({"user_id": [7], "home_lat": [NY[0]], "home_lon": [NY[1]]})
    return tx, geo, customers


def _run(tmp_path, tx, geo, customers, name):
    p = {k: tmp_path / f"{name}_{k}.parquet" for k in ("tx", "geo", "cust", "out")}
    tx.to_parquet(p["tx"], index=False)
    geo.to_parquet(p["geo"], index=False)
    customers.to_parquet(p["cust"], index=False)
    n = context.build_context(duckdb.connect(), p["tx"], p["geo"], p["cust"], p["out"])
    assert n == len(tx)
    return pd.read_parquet(p["out"]).set_index("tx_id").sort_index()


def test_haversine_macro():
    con = duckdb.connect()
    con.execute(context.HAVERSINE_MACRO)
    d = con.sql("SELECT haversine_km(48.8566, 2.3522, 51.5074, -0.1278) AS d").df()["d"].iloc[0]
    assert d == pytest.approx(343.5, rel=0.005)
    assert d == pytest.approx(haversine_py(48.8566, 2.3522, 51.5074, -0.1278))


def test_context_values(tmp_path):
    f = _run(tmp_path, *_data(), "v")
    d = haversine_py(*NY, *ROME)
    # tx 0 : premier achat, au domicile.
    assert f.loc[0, "dist_home_km"] == pytest.approx(0.0, abs=1e-6)
    assert pd.isna(f.loc[0, "dist_prev_km"]) and pd.isna(f.loc[0, "speed_kmh"])
    assert f.loc[0, "country_new"] and f.loc[0, "mcc_new"] and f.loc[0, "merchant_new"]
    assert pd.isna(f.loc[0, "amt_ratio_avg_90d"]) and f.loc[0, "n_purchases_90d"] == 0
    # tx 1 : Rome 1 h apres New York -> voyage impossible ; montant 10 fois l'habitude.
    assert f.loc[1, "dist_prev_km"] == pytest.approx(d)
    assert f.loc[1, "hours_since_prev_phys"] == pytest.approx(1.0)
    assert f.loc[1, "speed_kmh"] == pytest.approx(d)
    assert f.loc[1, "country_new"]
    assert f.loc[1, "amt_ratio_avg_90d"] == pytest.approx(10.0)
    assert pd.isna(f.loc[1, "amt_zscore_90d"])
    # tx 2 : en ligne -> pas de lieu ; MCC deja vu ; montant / moyenne(50, 500).
    assert pd.isna(f.loc[2, "dist_home_km"]) and pd.isna(f.loc[2, "speed_kmh"])
    assert pd.isna(f.loc[2, "country_new"])
    assert not f.loc[2, "mcc_new"]
    assert f.loc[2, "amt_ratio_avg_90d"] == pytest.approx(20 / 275)
    # tx 3 : autre carte, meme client. Achat physique precedent = Rome (tx 2 en ligne ignoree).
    assert pd.isna(f.loc[3, "amt_ratio_avg_90d"]) and f.loc[3, "n_purchases_90d"] == 0
    assert f.loc[3, "dist_prev_km"] == pytest.approx(d)
    assert f.loc[3, "hours_since_prev_phys"] == pytest.approx(23.0)
    assert f.loc[3, "speed_kmh"] == pytest.approx(d / 23)
    assert not f.loc[3, "country_new"]
    assert not f.loc[3, "mcc_new"]
    assert not f.loc[3, "merchant_new"]


def test_no_future_leakage(tmp_path):
    """Modifier ou ajouter des transactions FUTURES ne change pas les features du passe."""
    tx, geo, customers = _data()
    base = _run(tmp_path, tx, geo, customers, "base")

    tx2, geo2 = tx.copy(), geo.copy()
    tx2.loc[tx2["tx_id"] == 3, ["amount", "merchant_id"]] = [9999.0, "m9"]
    # tx 4 : meme minute que tx 2 mais apres elle -> invisible pour tx 2.
    tx_add = pd.DataFrame({
        "tx_id": [4, 5], "user_id": [7, 7], "card_id": ["A", "A"],
        "ts": pd.to_datetime(["2014-01-01 12:00", "2014-01-03 09:00"]).astype("datetime64[us]"),
        "amount": [800.0, 900.0], "mcc": [5732, 7011], "merchant_id": ["m3", "m4"],
        "merchant_country": ["Italy", "Japan"], "is_online": [False, False],
    })
    geo_add = pd.DataFrame({
        "tx_id": [4, 5], "merchant_lat": [ROME[0], 35.68], "merchant_lon": [ROME[1], 139.69],
        "geo_precision": ["city", "city"],
    })
    modifie = _run(tmp_path, pd.concat([tx2, tx_add], ignore_index=True),
                   pd.concat([geo2, geo_add], ignore_index=True), customers, "futur")

    pd.testing.assert_frame_equal(base.loc[[0, 1, 2]], modifie.loc[[0, 1, 2]])


def test_haversine_null_gives_null():
    """Regression : least() ignorait les NULL et renvoyait 20 015 km (demi-circonference)."""
    con = duckdb.connect()
    con.execute(context.HAVERSINE_MACRO)
    d = con.sql("SELECT haversine_km(NULL, NULL, 41.9, 12.5) AS d").df()["d"].iloc[0]
    assert pd.isna(d)
