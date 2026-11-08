import duckdb
import pandas as pd
import pytest

from secumon.ml.features import gold

FORBIDDEN = {
    "is_fraud", "merchant_country", "is_online", "tx_id", "user_id", "card_id", "ts", "split",
    "errors", "year_pin_last_changed", "expires_month", "cards_issued",
    "merchant_id", "merchant_city", "merchant_zip", "merchant_us_state",
}


def test_feature_list_has_no_forbidden_column():
    """Garantie verifiable : ni etiquette, ni pays, ni identifiant, ni colonne exclue."""
    assert not FORBIDDEN & set(gold.FEATURE_COLUMNS)
    assert len(gold.FEATURE_COLUMNS) == len(set(gold.FEATURE_COLUMNS))
    assert set(gold.EXCLUDED) <= FORBIDDEN


def _write(tmp_path, cards_ids=("U0007-C0",)):
    silver, features = tmp_path / "silver", tmp_path / "features"
    silver.mkdir()
    features.mkdir()
    pd.DataFrame({
        "tx_id": [0, 1], "user_id": [7, 7], "card_id": ["U0007-C0", "U0007-C0"],
        "ts": pd.to_datetime(["2014-03-05 09:07", "2016-01-02 23:59"]).astype("datetime64[us]"),
        "split": ["train", "test_a"], "is_fraud": [False, True],
        "merchant_country": ["United States", "Italy"], "is_online": [False, False],
        "amount": [134.09, 80.0], "is_refund": [False, False],
        "channel": ["swipe", "chip"], "mcc": [5300, 5732],
        "errors": [None, "Bad CVV"],
    }).to_parquet(silver / "transactions.parquet", index=False)
    pd.DataFrame({"tx_id": [0, 1], **{c: [0, 1] for c in [
        "n_tx_1h", "n_tx_24h", "n_tx_7d", "amt_sum_1h", "amt_sum_24h", "n_err_24h",
        "secs_since_prev"]}}).to_parquet(features / "velocity.parquet", index=False)
    pd.DataFrame({"tx_id": [0, 1], **{c: [0.0, 1.0] for c in [
        "amt_ratio_avg_90d", "amt_zscore_90d", "n_purchases_90d", "dist_home_km", "dist_prev_km",
        "hours_since_prev_phys", "speed_kmh"]},
        "country_new": [True, True], "mcc_new": [True, True], "merchant_new": [True, False],
    }).to_parquet(features / "context.parquet", index=False)
    pd.DataFrame({"user_id": [7], "birth_year": [1966], "yearly_income": [59696.0],
                  "total_debt": [127613.0], "fico_score": [787]}).to_parquet(
        silver / "customers.parquet", index=False)
    pd.DataFrame({"card_id": list(cards_ids), "user_id": [7] * len(cards_ids),
                  "acct_open_month": pd.to_datetime(["2002-09-01"] * len(cards_ids)),
                  "credit_limit": [24295.0] * len(cards_ids), "card_type": ["debit"] * len(cards_ids),
                  "card_brand": ["visa"] * len(cards_ids), "has_chip": [True] * len(cards_ids),
                  "year_pin_last_changed": [2008] * len(cards_ids)}).to_parquet(
        silver / "cards.parquet", index=False)
    return silver, features


def test_build_gold(tmp_path):
    silver, features = _write(tmp_path)
    out = tmp_path / "gold" / "gold.parquet"

    assert gold.build_gold(duckdb.connect(), silver, features, out) == 2

    df = pd.read_parquet(out).set_index("tx_id").sort_index()
    expected = set(gold.ID_COLUMNS + [gold.LABEL] + gold.SEGMENT_COLUMNS + gold.FEATURE_COLUMNS)
    assert set(df.reset_index().columns) == expected
    assert "errors" not in df.columns and "year_pin_last_changed" not in df.columns
    assert df.loc[0, "hour"] == 9
    assert df.loc[0, "day_of_week"] == 3          # 2014-03-05 est un mercredi (0 = dimanche)
    assert df.loc[0, "age_at_tx"] == 2014 - 1966
    assert df.loc[0, "account_age_months"] == 138  # septembre 2002 -> mars 2014
    assert df.loc[1, "split"] == "test_a"


def test_build_gold_detects_missing_join(tmp_path):
    """Une carte absente ferait disparaitre des transactions : le module doit s'arreter."""
    silver, features = _write(tmp_path, cards_ids=("U9999-C0",))
    with pytest.raises(RuntimeError, match="Jointure incomplete"):
        gold.build_gold(duckdb.connect(), silver, features, tmp_path / "gold.parquet")
