"""Table gold : une ligne par transaction, features + etiquette, prete pour l'entrainement.

Decisions anti-fuite :
- les erreurs de la transaction courante (resultat de l'autorisation) ne sont PAS des features ;
- les tables clients/cartes sont une photo de 2020 : year_pin_last_changed, expires_month et
  cards_issued sont exclues ; l'age et l'anciennete du compte sont calcules a la date de la
  transaction ; revenu, dette, FICO et plafond sont des approximations du profil ;
- merchant_country sert uniquement a segmenter l'evaluation, jamais de feature.
"""

from __future__ import annotations

from pathlib import Path

import duckdb

from secumon.ml.data.geo import _count
from secumon.ml.data.ibm import _sql_path

ID_COLUMNS = ["tx_id", "user_id", "card_id", "ts", "split"]
LABEL = "is_fraud"
SEGMENT_COLUMNS = ["merchant_country", "is_online"]
CATEGORICAL_FEATURES = ["channel", "mcc", "card_type", "card_brand"]
NUMERIC_FEATURES = [
    "amount", "is_refund", "hour", "day_of_week",
    "n_tx_1h", "n_tx_24h", "n_tx_7d", "amt_sum_1h", "amt_sum_24h", "n_err_24h", "secs_since_prev",
    "amt_ratio_avg_90d", "amt_zscore_90d", "n_purchases_90d", "dist_home_km", "dist_prev_km",
    "hours_since_prev_phys", "speed_kmh", "country_new", "mcc_new", "merchant_new",
    "age_at_tx", "account_age_months", "yearly_income", "total_debt", "fico_score",
    "credit_limit", "has_chip",
]
FEATURE_COLUMNS = NUMERIC_FEATURES + CATEGORICAL_FEATURES

EXCLUDED = {
    "errors": "resultat de l'autorisation en cours, inconnu au moment de la decision",
    "merchant_country": "segmentation de l'evaluation uniquement, pas de regle par pays",
    "year_pin_last_changed": "photo 2020, peut etre posterieure a la transaction",
    "expires_month": "photo 2020, date de la carte actuelle",
    "cards_issued": "photo 2020, cumul jusqu'a la fin du dataset",
}

GOLD_SQL = """
SELECT
    t.tx_id, t.user_id, t.card_id, t.ts, t.split,
    t.is_fraud,
    t.merchant_country, t.is_online,
    t.amount, t.is_refund, t.channel, t.mcc,
    CAST(hour(t.ts) AS INTEGER)                        AS hour,
    CAST(dayofweek(t.ts) AS INTEGER)                   AS day_of_week,
    v.n_tx_1h, v.n_tx_24h, v.n_tx_7d, v.amt_sum_1h, v.amt_sum_24h, v.n_err_24h,
    v.secs_since_prev,
    c.amt_ratio_avg_90d, c.amt_zscore_90d, c.n_purchases_90d, c.dist_home_km, c.dist_prev_km,
    c.hours_since_prev_phys, c.speed_kmh, c.country_new, c.mcc_new, c.merchant_new,
    year(t.ts) - cu.birth_year                         AS age_at_tx,
    -- Photo 2020 : une ouverture posterieure a la transaction est inconnue (NULL), pas negative.
    CASE WHEN date_diff('month', k.acct_open_month, t.ts) >= 0
         THEN date_diff('month', k.acct_open_month, t.ts) END  AS account_age_months,
    cu.yearly_income, cu.total_debt, cu.fico_score,
    k.credit_limit, k.card_type, k.card_brand, k.has_chip
FROM gold_tx t
JOIN gold_velocity v  ON v.tx_id = t.tx_id
JOIN gold_context c   ON c.tx_id = t.tx_id
JOIN gold_customers cu ON cu.user_id = t.user_id
JOIN gold_cards k     ON k.card_id = t.card_id
"""


def build_gold(con: duckdb.DuckDBPyConnection, silver_dir: str | Path,
               features_dir: str | Path, out: str | Path) -> int:
    """Ecrit la table gold (toutes periodes, colonne split) ; verifie le nombre de lignes."""
    silver_dir, features_dir, out = Path(silver_dir), Path(features_dir), Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    tx = _sql_path(silver_dir / "transactions.parquet")
    cust = _sql_path(silver_dir / "customers.parquet")
    cards = _sql_path(silver_dir / "cards.parquet")
    vel = _sql_path(features_dir / "velocity.parquet")
    ctx = _sql_path(features_dir / "context.parquet")
    dst = _sql_path(out)
    # Chemins internes valides par _sql_path : aucune entree utilisateur dans les requetes.
    con.execute(f"CREATE OR REPLACE VIEW gold_tx AS SELECT * FROM read_parquet('{tx}')")  # nosec B608
    con.execute(f"CREATE OR REPLACE VIEW gold_customers AS SELECT * FROM read_parquet('{cust}')")  # nosec B608
    con.execute(f"CREATE OR REPLACE VIEW gold_cards AS SELECT * FROM read_parquet('{cards}')")  # nosec B608
    con.execute(f"CREATE OR REPLACE VIEW gold_velocity AS SELECT * FROM read_parquet('{vel}')")  # nosec B608
    con.execute(f"CREATE OR REPLACE VIEW gold_context AS SELECT * FROM read_parquet('{ctx}')")  # nosec B608
    con.execute(f"CREATE OR REPLACE VIEW gold AS {GOLD_SQL}")
    con.execute(f"COPY gold TO '{dst}' (FORMAT parquet, COMPRESSION zstd)")
    n_in, n_out = _count(con, tx), _count(con, dst)
    if n_in != n_out:
        raise RuntimeError(f"Jointure incomplete : {n_in} transactions en entree, {n_out} en sortie")
    return n_out
