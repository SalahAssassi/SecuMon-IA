import duckdb
import pandas as pd
import pytest

from secumon.ml.data import geo


def _us_zip():
    return pd.DataFrame({
        "postal_code": ["94102", "94103", "62701"],
        "place": ["San Francisco", "San Francisco", "Springfield"],
        "state_code": ["CA", "CA", "IL"],
        "lat": [37.0, 38.0, 39.8],
        "lon": [-122.0, -123.0, -89.6],
    })


def _cities():
    # "Zuerich" en asciiname force le passage par les noms alternatifs dans le test.
    return pd.DataFrame({
        "iso2": ["CH", "CH", "XX", "XX"],
        "name": ["Zürich", "Geneva", "Big City", "Springfield"],
        "asciiname": ["Zuerich", "Geneva", "Big City", "Springfield"],
        "alternatenames": ["Zurich,Zuri", "", "", "Big City,Springy"],
        "lat": [47.37, 46.20, 1.0, 2.0],
        "lon": [8.54, 6.14, 1.0, 2.0],
        "population": [400000, 200000, 50, 100],
    })


def test_load_countries_adds_aliases(tmp_path):
    path = tmp_path / "countryInfo.txt"
    path.write_text("#ISO\tISO3\tISO-Numeric\tfips\tCountry\n"
                    "CH\tCHE\t756\tSZ\tSwitzerland\n"
                    "CZ\tCZE\t203\tEZ\tCzechia\n", encoding="utf-8")
    lookup = dict(zip(*geo.load_countries(path)[["country", "iso2"]].T.values))
    assert lookup["Switzerland"] == "CH"
    assert lookup["Czech Republic"] == "CZ"
    assert lookup["Swaziland"] == "SZ"


def test_us_lookups_average_zip_centroids():
    us_zip = _us_zip()
    city = geo.us_city_lookup(us_zip).set_index(["state_code", "city"])
    state = geo.us_state_lookup(us_zip).set_index("state_code")
    assert city.loc[("CA", "san francisco"), "lat"] == pytest.approx(37.5)
    assert state.loc["IL", "lat"] == pytest.approx(39.8)
    assert len(geo.zip_lookup(us_zip)) == 3


def test_world_city_lookup_prefers_exact_name():
    lookup = geo.world_city_lookup(_cities()).set_index(["iso2", "city"])
    assert lookup.loc[("XX", "big city"), "lat"] == pytest.approx(1.0)
    assert lookup.loc[("CH", "zurich"), "lat"] == pytest.approx(47.37)
    assert lookup.loc[("XX", "springy"), "lat"] == pytest.approx(2.0)
    assert not lookup.index.duplicated().any()


def test_country_lookup_uses_most_populous_city():
    lookup = geo.country_lookup(_cities()).set_index("iso2")
    assert lookup.loc["CH", "lat"] == pytest.approx(47.37)
    assert lookup.loc["XX", "lat"] == pytest.approx(2.0)


def test_resolve_cascade(tmp_path):
    tx = pd.DataFrame({
        "tx_id": [0, 1, 2, 3, 4, 5, 6],
        "is_online": [False, False, False, False, False, True, False],
        "merchant_zip": ["94102", "94101", "99999", None, None, None, None],
        "merchant_city": ["San Francisco", "San Francisco", "Nowhere", "Zurich",
                          "Lucerne", None, "Atlantis City"],
        "merchant_us_state": ["CA", "CA", "CA", None, None, None, None],
        "merchant_country": ["United States", "United States", "United States",
                             "Switzerland", "Switzerland", None, "Atlantis"],
    })
    src = tmp_path / "tx.parquet"
    tx.to_parquet(src, index=False)
    us_zip, cities = _us_zip(), _cities()
    tables = {
        "geo_zip": geo.zip_lookup(us_zip),
        "geo_us_city": geo.us_city_lookup(us_zip),
        "geo_us_state": geo.us_state_lookup(us_zip),
        "geo_country_iso": pd.DataFrame({"country": ["United States", "Switzerland"],
                                         "iso2": ["US", "CH"]}),
        "geo_world_city": geo.world_city_lookup(cities),
        "geo_country": geo.country_lookup(cities),
    }
    out = tmp_path / "geo" / "tx_geo.parquet"

    n = geo.resolve(duckdb.connect(), src, tables, out)

    assert n == 7
    df = pd.read_parquet(out).sort_values("tx_id").reset_index(drop=True)
    assert df["geo_precision"].tolist() == [
        "zip", "city", "region", "city", "region", "online", "unknown"]
    assert df.loc[0, "merchant_lat"] == pytest.approx(37.0)
    assert df.loc[1, "merchant_lat"] == pytest.approx(37.5)
    assert df.loc[2, "merchant_lat"] == pytest.approx(37.5)
    assert df.loc[3, "merchant_lat"] == pytest.approx(47.37)
    assert df.loc[4, "merchant_lat"] == pytest.approx(47.37)
    assert df.loc[[5, 6], ["merchant_lat", "merchant_lon"]].isna().all().all()
