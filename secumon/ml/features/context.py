"""Features contextuelles : montant relatif, geographie, nouveaute (anti-fuite).

- Montant : compare aux achats STRICTEMENT anterieurs de la meme carte (90 jours).
- Geographie : distance domicile -> commercant ; distance et vitesse depuis l'achat
  physique precedent du client (toutes cartes). La vitesse n'est calculee que si les
  deux lieux sont precis (zip ou city), pour eviter les fausses alertes.
- Nouveaute : premier pays / MCC / commercant jamais vu pour ce client.
Aucune regle de decision ici : ce sont des variables, le modele apprend leur poids.
"""

from __future__ import annotations

from pathlib import Path

import duckdb

from secumon.ml.data.geo import _count
from secumon.ml.data.ibm import _sql_path

HAVERSINE_MACRO = """
CREATE OR REPLACE MACRO haversine_km(lat1, lon1, lat2, lon2) AS
    2 * 6371.0088 * asin(sqrt(
        -- CASE et non least() : least() ignore les NULL et renverrait 1 (bug detecte par les tests).
        CASE WHEN pow(sin(radians(lat2 - lat1) / 2), 2)
                  + cos(radians(lat1)) * cos(radians(lat2)) * pow(sin(radians(lon2 - lon1) / 2), 2) > 1
             THEN 1.0
             ELSE pow(sin(radians(lat2 - lat1) / 2), 2)
                  + cos(radians(lat1)) * cos(radians(lat2)) * pow(sin(radians(lon2 - lon1) / 2), 2)
        END))
"""

CONTEXT_SQL = """
WITH base AS (
    SELECT t.tx_id, t.user_id, t.card_id, t.ts, t.amount, t.mcc, t.merchant_id,
           t.merchant_country, t.is_online,
           g.merchant_lat, g.merchant_lon, g.geo_precision,
           c.home_lat, c.home_lon,
           CAST(epoch(t.ts) AS BIGINT) * 1000
             + row_number() OVER (PARTITION BY t.card_id, t.ts ORDER BY t.tx_id) - 1 AS card_key,
           CAST(epoch(t.ts) AS BIGINT) * 1000
             + row_number() OVER (PARTITION BY t.user_id, t.ts ORDER BY t.tx_id) - 1 AS user_key
    FROM silver_tx t
    JOIN tx_geo g USING (tx_id)
    JOIN customers c USING (user_id)
),
amounts AS (
    SELECT tx_id,
           AVG(CASE WHEN amount > 0 THEN amount END) OVER w90         AS amt_avg_90d,
           STDDEV_SAMP(CASE WHEN amount > 0 THEN amount END) OVER w90 AS amt_std_90d,
           COUNT(CASE WHEN amount > 0 THEN 1 END) OVER w90            AS n_purchases_90d
    FROM base
    WINDOW w90 AS (PARTITION BY card_id ORDER BY card_key
                   RANGE BETWEEN 7776000000 PRECEDING AND 1 PRECEDING)
),
phys AS (
    SELECT tx_id, ts, merchant_lat, merchant_lon, geo_precision,
           LAG(merchant_lat)  OVER u AS prev_lat,
           LAG(merchant_lon)  OVER u AS prev_lon,
           LAG(ts)            OVER u AS prev_ts,
           LAG(geo_precision) OVER u AS prev_precision
    FROM base
    WHERE NOT is_online
    WINDOW u AS (PARTITION BY user_id ORDER BY user_key)
),
travel AS (
    SELECT tx_id,
           haversine_km(prev_lat, prev_lon, merchant_lat, merchant_lon) AS dist_prev_km,
           (epoch(ts) - epoch(prev_ts)) / 3600.0                        AS hours_since_prev_phys,
           CASE WHEN geo_precision IN ('zip', 'city') AND prev_precision IN ('zip', 'city')
                THEN haversine_km(prev_lat, prev_lon, merchant_lat, merchant_lon)
                     / GREATEST((epoch(ts) - epoch(prev_ts)) / 3600.0, 1.0 / 60)
           END                                                          AS speed_kmh
    FROM phys
),
firsts AS (
    SELECT tx_id,
           CASE WHEN is_online THEN NULL
                ELSE row_number() OVER (PARTITION BY user_id, merchant_country ORDER BY user_key) = 1
           END                                                                    AS country_new,
           row_number() OVER (PARTITION BY user_id, mcc ORDER BY user_key) = 1         AS mcc_new,
           row_number() OVER (PARTITION BY user_id, merchant_id ORDER BY user_key) = 1 AS merchant_new
    FROM base
)
SELECT b.tx_id,
       b.amount / NULLIF(a.amt_avg_90d, 0)                   AS amt_ratio_avg_90d,
       (b.amount - a.amt_avg_90d) / NULLIF(a.amt_std_90d, 0) AS amt_zscore_90d,
       a.n_purchases_90d,
       CASE WHEN b.is_online THEN NULL
            ELSE haversine_km(b.home_lat, b.home_lon, b.merchant_lat, b.merchant_lon)
       END                                                   AS dist_home_km,
       tr.dist_prev_km,
       tr.hours_since_prev_phys,
       tr.speed_kmh,
       f.country_new,
       f.mcc_new,
       f.merchant_new
FROM base b
JOIN amounts a USING (tx_id)
JOIN firsts f USING (tx_id)
LEFT JOIN travel tr USING (tx_id)
"""


def build_context(con: duckdb.DuckDBPyConnection, silver_tx: str | Path, tx_geo: str | Path,
                  customers: str | Path, out: str | Path) -> int:
    """Ecrit les features contextuelles (une ligne par tx_id) ; verifie le nombre de lignes."""
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    tx, geo, cust, dst = (_sql_path(p) for p in (silver_tx, tx_geo, customers, out))
    # Chemins internes valides par _sql_path : aucune entree utilisateur dans les requetes.
    con.execute(f"CREATE OR REPLACE VIEW silver_tx AS SELECT * FROM read_parquet('{tx}')")  # nosec B608
    con.execute(f"CREATE OR REPLACE VIEW tx_geo AS SELECT * FROM read_parquet('{geo}')")  # nosec B608
    con.execute(f"CREATE OR REPLACE VIEW customers AS SELECT * FROM read_parquet('{cust}')")  # nosec B608
    con.execute(HAVERSINE_MACRO)
    con.execute(f"CREATE OR REPLACE VIEW tx_context AS {CONTEXT_SQL}")
    con.execute(f"COPY tx_context TO '{dst}' (FORMAT parquet, COMPRESSION zstd)")
    n_in, n_out = _count(con, tx), _count(con, dst)
    if n_in != n_out:
        raise RuntimeError(f"Nombre de lignes incorrect : {n_in} en entree, {n_out} en sortie")
    return n_out
