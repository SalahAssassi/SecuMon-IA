
"""Features de velocite par carte, calculees uniquement sur le passe (anti-fuite).

Les fenetres ne contiennent que les transactions STRICTEMENT anterieures de la meme carte.
Les horodatages sont a la minute : dans une meme minute, l'ordre est donne par tx_id
(ordre chronologique du fichier d'origine). La seconde transaction voit la premiere,
jamais l'inverse.
"""

from __future__ import annotations

from pathlib import Path

import duckdb

from secumon.ml.data.geo import _count
from secumon.ml.data.ibm import _sql_path

# t_key = secondes * 1000 + rang dans la minute : cle d'ordre unique par carte.
# Les minutes sont espacees de 60 000 unites, donc aucune collision possible en pratique.
VELOCITY_SQL = """
WITH base AS (
    SELECT tx_id, card_id, ts, amount, errors,
           CAST(epoch(ts) AS BIGINT) * 1000
             + row_number() OVER (PARTITION BY card_id, ts ORDER BY tx_id) - 1 AS t_key
    FROM silver_tx
)
SELECT
    tx_id,
    COUNT(*) OVER w1h                                                 AS n_tx_1h,
    COUNT(*) OVER w24h                                                AS n_tx_24h,
    COUNT(*) OVER w7d                                                 AS n_tx_7d,
    COALESCE(SUM(CASE WHEN amount > 0 THEN amount END) OVER w1h, 0)   AS amt_sum_1h,
    COALESCE(SUM(CASE WHEN amount > 0 THEN amount END) OVER w24h, 0)  AS amt_sum_24h,
    COUNT(errors) OVER w24h                                           AS n_err_24h,
    epoch(ts) - epoch(LAG(ts) OVER (PARTITION BY card_id ORDER BY t_key)) AS secs_since_prev
FROM base
WINDOW
    w1h  AS (PARTITION BY card_id ORDER BY t_key
             RANGE BETWEEN 3600000 PRECEDING AND 1 PRECEDING),
    w24h AS (PARTITION BY card_id ORDER BY t_key
             RANGE BETWEEN 86400000 PRECEDING AND 1 PRECEDING),
    w7d  AS (PARTITION BY card_id ORDER BY t_key
             RANGE BETWEEN 604800000 PRECEDING AND 1 PRECEDING)
"""


def build_velocity(con: duckdb.DuckDBPyConnection, silver_tx: str | Path, out: str | Path) -> int:
    """Ecrit les features de velocite (une ligne par tx_id) ; verifie le nombre de lignes."""
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    src, dst = _sql_path(silver_tx), _sql_path(out)
    # Chemins internes valides par _sql_path : aucune entree utilisateur dans les requetes.
    con.execute(f"CREATE OR REPLACE VIEW silver_tx AS SELECT * FROM read_parquet('{src}')")  # nosec B608
    con.execute(f"CREATE OR REPLACE VIEW tx_velocity AS {VELOCITY_SQL}")
    con.execute(f"COPY tx_velocity TO '{dst}' (FORMAT parquet, COMPRESSION zstd)")
    n_in, n_out = _count(con, src), _count(con, dst)
    if n_in != n_out:
        raise RuntimeError(f"Nombre de lignes incorrect : {n_in} en entree, {n_out} en sortie")
    return n_out
