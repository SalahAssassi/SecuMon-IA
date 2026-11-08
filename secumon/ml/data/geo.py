"""Enrichissement geographique des commercants (GeoNames.org, licence CC BY 4.0).

Cascade de precision : zip -> city -> region -> unknown.
Les achats en ligne n'ont pas de lieu physique (precision 'online', sans coordonnees).
"""

from __future__ import annotations

import csv
from pathlib import Path

import duckdb
import pandas as pd

from secumon.ml.data.ibm import _sql_path

# Noms de pays du dataset IBM absents de GeoNames -> code ISO 3166-1 alpha-2.
COUNTRY_ALIASES = {
    "Netherlands": "NL", "The Bahamas": "BS", "Czech Republic": "CZ",
    "Vatican City": "VA", "Macedonia": "MK", "Cote d'Ivoire": "CI",
    "Myanmar (Burma)": "MM", "East Timor (Timor-Leste)": "TL", "Swaziland": "SZ",
}

# Colonnes documentees dans les readme.txt de GeoNames (fichiers sans en-tete).
US_COLS = ["country", "postal_code", "place", "state_name", "state_code", "county_name",
           "county_code", "admin3_name", "admin3_code", "lat", "lon", "accuracy"]
CITY_COLS = ["geonameid", "name", "asciiname", "alternatenames", "lat", "lon",
             "feature_class", "feature_code", "country_code", "cc2", "admin1", "admin2",
             "admin3", "admin4", "population", "elevation", "dem", "timezone", "modified"]


def _read_tsv(path: str | Path, names: list[str]) -> pd.DataFrame:
    # keep_default_na=False : sinon le code pays "NA" (Namibie) deviendrait une valeur manquante.
    return pd.read_csv(path, sep="\t", header=None, names=names, dtype=str,
                       quoting=csv.QUOTE_NONE, keep_default_na=False)


def load_us_zip(path: str | Path) -> pd.DataFrame:
    raw = _read_tsv(path, US_COLS)
    return pd.DataFrame({
        "postal_code": raw["postal_code"],
        "place": raw["place"],
        "state_code": raw["state_code"],
        "lat": raw["lat"].astype(float),
        "lon": raw["lon"].astype(float),
    })


def load_cities(path: str | Path) -> pd.DataFrame:
    raw = _read_tsv(path, CITY_COLS)
    return pd.DataFrame({
        "iso2": raw["country_code"],
        "name": raw["name"],
        "asciiname": raw["asciiname"],
        "alternatenames": raw["alternatenames"],
        "lat": raw["lat"].astype(float),
        "lon": raw["lon"].astype(float),
        "population": pd.to_numeric(raw["population"], errors="coerce").fillna(0).astype("int64"),
    })


def load_countries(path: str | Path) -> pd.DataFrame:
    """Table nom de pays -> code ISO, completee par COUNTRY_ALIASES."""
    rows = [line.split("\t") for line in Path(path).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")]
    names = pd.DataFrame([[r[4], r[0]] for r in rows], columns=["country", "iso2"])
    aliases = pd.DataFrame(list(COUNTRY_ALIASES.items()), columns=["country", "iso2"])
    table = pd.concat([names, aliases], ignore_index=True)
    if table["country"].duplicated().any():
        raise ValueError("Nom de pays en double dans la table des pays")
    return table


def zip_lookup(us_zip: pd.DataFrame) -> pd.DataFrame:
    return us_zip.groupby("postal_code", as_index=False)[["lat", "lon"]].mean()


def us_city_lookup(us_zip: pd.DataFrame) -> pd.DataFrame:
    df = us_zip.assign(city=us_zip["place"].str.lower())
    return df.groupby(["state_code", "city"], as_index=False)[["lat", "lon"]].mean()


def us_state_lookup(us_zip: pd.DataFrame) -> pd.DataFrame:
    return us_zip.groupby("state_code", as_index=False)[["lat", "lon"]].mean()


def world_city_lookup(cities: pd.DataFrame) -> pd.DataFrame:
    """(pays, ville en minuscules) -> coordonnees.

    Priorite au nom officiel (name, asciiname) sur les noms alternatifs ;
    a priorite egale, la ville la plus peuplee l'emporte.
    """
    cols = ["iso2", "lat", "lon", "population"]
    exact = pd.concat([
        cities[cols].assign(alias=cities["name"]),
        cities[cols].assign(alias=cities["asciiname"]),
    ]).assign(priority=0)
    alt = (cities[cols].assign(alias=cities["alternatenames"].str.split(","))
           .explode("alias").assign(priority=1))
    names = pd.concat([exact, alt], ignore_index=True)
    names["city"] = names["alias"].fillna("").str.strip().str.lower()
    names = names[names["city"] != ""]
    names = names.sort_values(["priority", "population"], ascending=[True, False])
    return names.drop_duplicates(["iso2", "city"])[["iso2", "city", "lat", "lon"]].reset_index(drop=True)


def country_lookup(cities: pd.DataFrame) -> pd.DataFrame:
    """Repli par pays : coordonnees de la ville la plus peuplee du pays."""
    best = cities.sort_values("population", ascending=False).drop_duplicates("iso2")
    return best[["iso2", "lat", "lon"]].reset_index(drop=True)


GEO_SQL = """
SELECT
    t.tx_id,
    CASE WHEN t.is_online THEN NULL
         ELSE COALESCE(z.lat, uc.lat, wc.lat, us.lat, cc.lat) END  AS merchant_lat,
    CASE WHEN t.is_online THEN NULL
         ELSE COALESCE(z.lon, uc.lon, wc.lon, us.lon, cc.lon) END  AS merchant_lon,
    CASE WHEN t.is_online                               THEN 'online'
         WHEN z.lat IS NOT NULL                         THEN 'zip'
         WHEN uc.lat IS NOT NULL OR wc.lat IS NOT NULL THEN 'city'
         WHEN us.lat IS NOT NULL OR cc.lat IS NOT NULL THEN 'region'
         ELSE 'unknown'
    END                                                            AS geo_precision
FROM silver_tx t
LEFT JOIN geo_zip z          ON t.merchant_zip = z.postal_code
LEFT JOIN geo_us_city uc     ON t.merchant_us_state = uc.state_code
                            AND lower(t.merchant_city) = uc.city
LEFT JOIN geo_us_state us    ON t.merchant_us_state = us.state_code
LEFT JOIN geo_country_iso p  ON t.merchant_country = p.country AND p.iso2 <> 'US'
LEFT JOIN geo_world_city wc  ON p.iso2 = wc.iso2 AND lower(t.merchant_city) = wc.city
LEFT JOIN geo_country cc     ON p.iso2 = cc.iso2
"""


def _count(con: duckdb.DuckDBPyConnection, sql_path: str) -> int:
    return int(con.sql(f"SELECT COUNT(*) AS n FROM read_parquet('{sql_path}')").df()["n"].iloc[0])  # nosec B608


def resolve(con: duckdb.DuckDBPyConnection, silver_tx: str | Path,
            tables: dict[str, pd.DataFrame], out: str | Path) -> int:
    """Ecrit (tx_id, merchant_lat, merchant_lon, geo_precision) ; verifie le nombre de lignes."""
    for name, df in tables.items():
        con.register(name, df)
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    src, dst = _sql_path(silver_tx), _sql_path(out)
    con.execute(f"CREATE OR REPLACE VIEW silver_tx AS SELECT * FROM read_parquet('{src}')")  # nosec B608
    con.execute(f"CREATE OR REPLACE VIEW tx_geo AS {GEO_SQL}")
    con.execute(f"COPY tx_geo TO '{dst}' (FORMAT parquet, COMPRESSION zstd)")
    n_in, n_out = _count(con, src), _count(con, dst)
    if n_in != n_out:
        raise RuntimeError(f"Jointure incorrecte : {n_in} transactions en entree, {n_out} en sortie")
    return n_out


def build_tx_geo(con: duckdb.DuckDBPyConnection, silver_tx: str | Path,
                 geo_dir: str | Path, out: str | Path) -> int:
    geo_dir = Path(geo_dir)
    us_zip = load_us_zip(geo_dir / "us_zip" / "US.txt")
    cities = load_cities(geo_dir / "cities15000.txt")
    tables = {
        "geo_zip": zip_lookup(us_zip),
        "geo_us_city": us_city_lookup(us_zip),
        "geo_us_state": us_state_lookup(us_zip),
        "geo_country_iso": load_countries(geo_dir / "countryInfo.txt"),
        "geo_world_city": world_city_lookup(cities),
        "geo_country": country_lookup(cities),
    }
    return resolve(con, silver_tx, tables, out)
