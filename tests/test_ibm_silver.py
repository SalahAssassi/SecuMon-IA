import duckdb
import pandas as pd
import pytest

from secumon.ml.data import ibm

USERS_CSV = (
    "Person,Current Age,Retirement Age,Birth Year,Birth Month,Gender,Address,Apartment,"
    "City,State,Zipcode,Latitude,Longitude,Per Capita Income - Zipcode,"
    "Yearly Income - Person,Total Debt,FICO Score,Num Credit Cards\n"
    "Fictif Un,53,66,1966,11,Female,1 Rue Fictive,,Springfield,CA,01234,34.15,-117.76,"
    "$29278,$59696,$127613,787,5\n"
    "Fictif Deux,40,67,1979,3,Male,2 Rue Fictive,4,Austin,TX,73301,30.27,-97.74,"
    "$9,$1000,$0,700,1\n"
)

CARDS_HEADER = (
    "User,CARD INDEX,Card Brand,Card Type,Card Number,Expires,CVV,Has Chip,"
    "Cards Issued,Credit Limit,Acct Open Date,Year PIN last Changed,Card on Dark Web\n"
)
CARDS_ROWS = (
    "0,0,Visa,Debit,1111222233334444,12/2022,623,YES,2,$24295,09/2002,2008,No\n"
    "0,1,Amex,Debit (Prepaid),111122223333444,03/2024,111,NO,1,$55,01/2010,2015,No\n"
)


def test_parse_money_handles_dollar_and_negative():
    s = pd.Series(["$134.09", "$-500.00", "$0"])
    assert ibm.parse_money(s).tolist() == [134.09, -500.0, 0.0]


def test_parse_money_rejects_garbage():
    with pytest.raises(ValueError):
        ibm.parse_money(pd.Series(["abc"]))


def test_split_for_year():
    years = (1991, 2014, 2015, 2016, 2017, 2020)
    assert [ibm.split_for_year(y) for y in years] == [
        "train", "train", "validation", "test_a", "test_b", "test_b"]


def test_sql_split_matches_python():
    assert f"<= {ibm.TRAIN_LAST_YEAR} THEN 'train'" in ibm.TRANSACTIONS_SQL
    assert f"=  {ibm.VALIDATION_YEAR} THEN 'validation'" in ibm.TRANSACTIONS_SQL
    assert f"=  {ibm.TEST_A_YEAR} THEN 'test_a'" in ibm.TRANSACTIONS_SQL


def test_card_id_format():
    assert ibm.card_id(7, 2) == "U0007-C2"


def test_load_customers_minimises_pii(tmp_path):
    path = tmp_path / "users.csv"
    path.write_text(USERS_CSV)
    df = ibm.load_customers(path)
    assert df["user_id"].tolist() == [0, 1]
    assert df["yearly_income"].tolist() == [59696.0, 1000.0]
    assert df["home_zip"].tolist() == ["01234", "73301"]
    for col in ("Person", "Address", "Apartment", "Gender"):
        assert col not in df.columns
    assert "Fictif" not in df.to_string()
    assert "Rue Fictive" not in df.to_string()


def test_load_cards_minimises_pii(tmp_path):
    path = tmp_path / "cards.csv"
    path.write_text(CARDS_HEADER + CARDS_ROWS)
    df = ibm.load_cards(path)
    assert df["card_id"].tolist() == ["U0000-C0", "U0000-C1"]
    assert df["card_type"].tolist() == ["debit", "prepaid"]
    assert df["has_chip"].tolist() == [True, False]
    assert df["credit_limit"].tolist() == [24295.0, 55.0]
    assert df["expires_month"].iloc[0] == pd.Timestamp("2022-12-01")
    for col in ("Card Number", "CVV", "Card on Dark Web"):
        assert col not in df.columns
    assert "1111222233334444" not in df.to_string()


def test_load_cards_rejects_unknown_type(tmp_path):
    path = tmp_path / "cards.csv"
    path.write_text(CARDS_HEADER + CARDS_ROWS.replace("Visa,Debit,", "Visa,Gold,"))
    with pytest.raises(ValueError, match="Card Type"):
        ibm.load_cards(path)


def test_build_transactions(tmp_path):
    cols = ["User", "Card", "Year", "Month", "Day", "Time", "Amount", "Use Chip",
            "Merchant Name", "Merchant City", "Merchant State", "Zip", "MCC",
            "Errors?", "Is Fraud?"]
    rows = [
        ["0", "0", "2014", "3", "5", "09:07", "$134.09", "Swipe Transaction",
         "-7276", "La Verne", "CA", "501.0", "5300", None, "No"],
        ["0", "0", "2016", "1", "2", "23:59", "$-500.00", "Online Transaction",
         "123", "ONLINE", None, None, "4829", None, "No"],
        ["12", "1", "2018", "7", "9", "10:30", "$80.00", "Chip Transaction",
         "456", "Rome", "Italy", None, "5732", "Bad CVV", "Yes"],
    ]
    bronze = tmp_path / "bronze.parquet"
    pd.DataFrame(rows, columns=cols).to_parquet(bronze, index=False)
    out = tmp_path / "silver" / "transactions.parquet"

    n = ibm.build_transactions(duckdb.connect(), bronze, out)

    assert n == 3
    df = pd.read_parquet(out).sort_values("tx_id").reset_index(drop=True)
    assert df["tx_id"].tolist() == [0, 1, 2]
    assert df["card_id"].tolist() == ["U0000-C0", "U0000-C0", "U0012-C1"]
    assert df.loc[0, "ts"] == pd.Timestamp("2014-03-05 09:07")
    assert df["amount"].tolist() == pytest.approx([134.09, -500.0, 80.0])
    assert df["is_refund"].tolist() == [False, True, False]
    assert df["channel"].tolist() == ["swipe", "online", "chip"]
    assert df["is_online"].tolist() == [False, True, False]
    assert df["merchant_city"].isna().tolist() == [False, True, False]
    assert df.loc[0, "merchant_us_state"] == "CA"
    assert df.loc[0, "merchant_country"] == "United States"
    assert df["merchant_country"].isna().tolist() == [False, True, False]
    assert df.loc[2, "merchant_country"] == "Italy"
    assert df.loc[0, "merchant_zip"] == "00501"
    assert df["is_fraud"].tolist() == [False, False, True]
    assert df["split"].tolist() == ["train", "test_a", "test_b"]
