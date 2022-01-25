import psycopg2
from dotenv import load_dotenv
import os
import yaml
import json

load_dotenv()

DB_HOST = os.environ.get("DB_HOST") or "127.0.0.1"
DB_PORT = os.environ.get("DB_PORT") or "5432"
DB_USER = os.environ.get("DB_USER") or "postgres"
DB_PASSWORD = os.environ.get("DB_PASSWORD")
DB_NAME = os.environ.get("DB_NAME") or "postgres"

SUBDOMAINS_FILE = "subdomains.yaml"
WHOIS_FILE = "whois_data.yaml"

conn = psycopg2.connect(
    dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT
)
c = conn.cursor()


def create_tables() -> bool:
    with conn:
        try:
            c.execute(
                """CREATE TABLE IF NOT EXISTS Domains (
                    id SERIAL PRIMARY KEY,
                    domain TEXT UNIQUE,
                    registrar TEXT,
                    creation_date TEXT,
                    expiration_date TEXT
                )"""
            )
        except Exception as e:
            print(e)
            return False

        try:
            c.execute(
                """CREATE TABLE IF NOT EXISTS Subdomains (
                    domain TEXT,
                    subdomain TEXT UNIQUE
                )"""
            )
        except Exception as e:
            print(e)
            return False
    return True


def load_data():
    subdomains_data: dict
    whois_data: dict

    if SUBDOMAINS_FILE.endswith(".json"):
        with open(SUBDOMAINS_FILE, "r") as f:
            subdomains_data = json.load(f)
    elif SUBDOMAINS_FILE.endswith((".yaml", ".yml")):
        with open(SUBDOMAINS_FILE, "rb") as f:
            subdomains_data = yaml.safe_load(f)
    else:
        print("Unsupported file type.")
        exit()

    if WHOIS_FILE.endswith(".json"):
        with open(WHOIS_FILE, "r") as f:
            whois_data = json.load(f)
    elif WHOIS_FILE.endswith((".yaml", ".yml")):
        with open(WHOIS_FILE, "rb") as f:
            whois_data = yaml.safe_load(f)
    else:
        print("Unsupported file type.")
        exit()

    return subdomains_data, whois_data


def add_whois_records(whois_data: dict, conn, c):
    with conn:
        for domain in whois_data:
            registrar = whois_data[domain]["registrar"]
            creation_date = whois_data[domain]["creation_date"]
            expiration_date = whois_data[domain]["expiration_date"]

            # https://stackoverflow.com/a/1109198/14892434
            c.execute(
                "INSERT INTO Domains (domain, registrar, creation_date, expiration_date) VALUES (%s, %s, %s, %s) ON CONFLICT (domain) DO UPDATE SET domain = %s, registrar = %s, creation_date = %s, expiration_date = %s",
                (
                    domain,
                    registrar,
                    creation_date,
                    expiration_date,
                    domain,
                    registrar,
                    creation_date,
                    expiration_date,
                ),
            )


def add_subdomain_records(subdomains_data: dict, conn, c):
    with conn:
        for domain in subdomains_data:
            c.execute("DELETE FROM Subdomains WHERE domain = %s", (domain,))
            for subdomain in subdomains_data[domain]:
                # add new records
                c.execute(
                    "INSERT INTO Subdomains (domain, subdomain) VALUES (%s, %s)",
                    (domain, subdomain),
                )


def main():
    create_tables()
    subdomains_data, whois_data = load_data()

    add_whois_records(whois_data, conn, c)
    add_subdomain_records(subdomains_data, conn, c)


if __name__ == "__main__":
    main()
