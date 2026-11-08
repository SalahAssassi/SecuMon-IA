"""Couche silver du dataset IBM (donnees synthetiques).

Nettoyage, typage et minimisation des donnees :
- supprimees : nom, adresse, appartement, genre, numero de carte, CVV ;
- l'identifiant client est la position de la ligne dans sd254_users.csv.
"""

from __future__ import annotations

from pathlib import Path

import duckdb
import pandas as pd

# Decoupage temporel retenu dans le notebook 02.
TRAIN_LAST_YEAR = 2014
VALIDATION_YEAR = 2015
TEST_A_YEAR = 2016

CARD_TYPES = {"Credit": "credit", "Debit": "debit", "Debit (Prepaid)": "prepaid"}
CHIP_VALUES = {"YES": True, "NO": False}

TRANSACTIONS_SQL = """
SELECT
    file_row_number                                        AS tx_id,
    CAST("User" AS INTEGER)                                AS user_id,
    CAST("Card" AS INTEGER)                                AS card_idx,
    'U' || lpad("User", 4, '0') || '-C' || "Card"          AS card_id,
    make_timestamp(
        CAST("Year" AS BIGINT), CAST("Month" AS BIGINT), CAST("Day" AS BIGINT),
        CAST(split_part("Time", ':', 1) AS BIGINT),
        CAST(split_part("Time", ':', 2) AS BIGINT), 0.0)   AS ts,
    ROUND(CAST(REPLACE("Amount", '$', '') AS DOUBLE), 2)   AS amount,
    CAST(REPLACE("Amount", '$', '') AS DOUBLE) < 0         AS is_refund,
    CASE "Use Chip"
        WHEN 'Swipe Transaction'  THEN 'swipe'
        WHEN 'Chip Transaction'   THEN 'chip'
        WHEN 'Online Transaction' THEN 'online'
    END                                                    AS channel,
    "Merchant City" = 'ONLINE'                             AS is_online,
    "Merchant Name"                                        AS merchant_id,
    NULLIF("Merchant City", 'ONLINE')                      AS merchant_city,
    CASE WHEN length("Merchant State") = 2
         THEN "Merchant State" END                         AS merchant_us_state,
    CASE WHEN "Merchant City" = 'ONLINE'    THEN NULL
         WHEN length("Merchant State") = 2 THEN 'United States'
         ELSE NULLIF("Merchant State", '')
    END                                                    AS merchant_country,
    lpad(CAST(CAST(TRY_CAST("Zip" AS DOUBLE) AS INTEGER) AS VARCHAR), 5, '0')
                                                           AS merchant_zip,
    CAST("MCC" AS INTEGER)                                 AS mcc,
    NULLIF("Errors?", '')                                  AS errors,
    "Is Fraud?" = 'Yes'                                    AS is_fraud,
    CASE WHEN CAST("Year" AS INTEGER) <= 2014 THEN 'train'
         WHEN CAST("Year" AS INTEGER) =  2015 THEN 'validation'
         WHEN CAST("Year" AS INTEGER) =  2016 THEN 'test_a'
         ELSE 'test_b'
    END                                                    AS split
FROM bronze
"""


def split_for_year(year: int) -> str:
    """Jeu de donnees (train, validation, test_a, test_b) d'une annee."""
    if year <= TRAIN_LAST_YEAR:
        return "train"
    if year == VALIDATION_YEAR:
        return "validation"
    if year == TEST_A_YEAR:
        return "test_a"
    return "test_b"


def card_id(user_id: int, card_idx: int) -> str:
    """Identifiant interne de carte, sans lien avec le numero de carte."""
    return f"U{user_id:04d}-C{card_idx}"


def parse_money(s: pd.Series) -> pd.Series:
    """'$59696' -> 59696.0 ; '$-500.00' -> -500.0 ; leve ValueError si invalide."""
    cleaned = s.str.replace("$", "", regex=False)
    return pd.to_numeric(cleaned, errors="raise").astype("float64")


def _map_strict(s: pd.Series, mapping: dict, column: str) -> pd.Series:
    unknown = sorted(set(s.dropna().unique()) - set(mapping))
    if unknown:
        raise ValueError(f"{column} : valeurs inattendues {unknown}")
    return s.map(mapping)


def load_customers(path: str | Path) -> pd.DataFrame:
    """Profils clients sans identifiants directs (nom, adresse, appartement, genre)."""
    raw = pd.read_csv(path, dtype=str)
    return pd.DataFrame({
        "user_id": range(len(raw)),
        "birth_year": raw["Birth Year"].astype(int),
        "home_city": raw["City"],
        "home_state": raw["State"],
        "home_zip": raw["Zipcode"].str.zfill(5),
        "home_lat": raw["Latitude"].astype(float),
        "home_lon": raw["Longitude"].astype(float),
        "zip_income_per_capita": parse_money(raw["Per Capita Income - Zipcode"]),
        "yearly_income": parse_money(raw["Yearly Income - Person"]),
        "total_debt": parse_money(raw["Total Debt"]),
        "fico_score": raw["FICO Score"].astype(int),
        "num_credit_cards": raw["Num Credit Cards"].astype(int),
    })


def load_cards(path: str | Path) -> pd.DataFrame:
    """Cartes sans numero ni CVV."""
    raw = pd.read_csv(path, dtype=str)
    user = raw["User"].astype(int)
    idx = raw["CARD INDEX"].astype(int)
    return pd.DataFrame({
        "user_id": user,
        "card_idx": idx,
        "card_id": [card_id(u, c) for u, c in zip(user, idx)],
        "card_brand": raw["Card Brand"].str.lower(),
        "card_type": _map_strict(raw["Card Type"], CARD_TYPES, "Card Type"),
        "has_chip": _map_strict(raw["Has Chip"], CHIP_VALUES, "Has Chip").astype(bool),
        "cards_issued": raw["Cards Issued"].astype(int),
        "credit_limit": parse_money(raw["Credit Limit"]),
        "expires_month": pd.to_datetime(raw["Expires"], format="%m/%Y"),
        "acct_open_month": pd.to_datetime(raw["Acct Open Date"], format="%m/%Y"),
        "year_pin_last_changed": raw["Year PIN last Changed"].astype(int),
    })


def _sql_path(path: str | Path) -> str:
    """Chemin absolu utilisable dans une requete DuckDB ; refuse les apostrophes."""
    text = Path(path).resolve().as_posix()
    if "'" in text:
        raise ValueError(f"Chemin refuse (apostrophe) : {text}")
    return text


def build_transactions(con: duckdb.DuckDBPyConnection, bronze: str | Path, out: str | Path) -> int:
    """Ecrit les transactions silver en Parquet et renvoie le nombre de lignes."""
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    src, dst = _sql_path(bronze), _sql_path(out)
    # Chemins internes valides par _sql_path : aucune entree utilisateur dans les requetes.
    con.execute(f"CREATE OR REPLACE VIEW bronze AS SELECT * FROM read_parquet('{src}', file_row_number = true)")  # nosec B608
    con.execute(f"CREATE OR REPLACE VIEW silver_transactions AS {TRANSACTIONS_SQL}")
    con.execute(f"COPY silver_transactions TO '{dst}' (FORMAT parquet, COMPRESSION zstd)")
    count = con.sql(f"SELECT COUNT(*) AS n FROM read_parquet('{dst}')").df()["n"].iloc[0]  # nosec B608
    return int(count)


def build_silver(raw_dir: str | Path, bronze: str | Path, out_dir: str | Path) -> dict[str, int]:
    """Construit customers, cards et transactions dans out_dir."""
    raw_dir, out_dir = Path(raw_dir), Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    customers = load_customers(raw_dir / "sd254_users.csv")
    cards = load_cards(raw_dir / "sd254_cards.csv")
    customers.to_parquet(out_dir / "customers.parquet", index=False)
    cards.to_parquet(out_dir / "cards.parquet", index=False)
    con = duckdb.connect()
    try:
        n_tx = build_transactions(con, bronze, out_dir / "transactions.parquet")
    finally:
        con.close()
    return {"customers": len(customers), "cards": len(cards), "transactions": n_tx}
