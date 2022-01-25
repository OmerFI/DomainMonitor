from flask_restful import Resource, reqparse
from pathlib import Path
from dotenv import load_dotenv, find_dotenv
import os
import sys
import psycopg2
import threading

load_dotenv(find_dotenv())

BASEDIR = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(BASEDIR))
import subfinder
import whois_scan
import db

DB_HOST = os.environ.get("DB_HOST") or "127.0.0.1"
DB_PORT = os.environ.get("DB_PORT") or "5432"
DB_USER = os.environ.get("DB_USER") or "postgres"
DB_PASSWORD = os.environ.get("DB_PASSWORD")
DB_NAME = os.environ.get("DB_NAME") or "postgres"

SUBDOMAINS_FILE = BASEDIR / "subdomains.yaml"
WHOIS_FILE = BASEDIR / "whois_data.yaml"

conn = psycopg2.connect(
    dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT
)
c = conn.cursor()

db.create_tables()

reqargs = reqparse.RequestParser()
reqargs.add_argument(
    name="fields",
    type=str,
    help="What fields of the whois query the api will return. Should be separated by commas.",
    required=False,
)


class Whois(Resource):
    def get(self, domain):
        args = reqargs.parse_args(strict=True)
        if args.get("fields"):
            fields = list(map(str.strip, args.get("fields").split(",")))
        else:
            fields = ["registrar", "creation_date", "expiration_date"]
        with conn:
            c.execute(
                f"SELECT {','.join(fields)} from Domains where domain = %s", (domain,)
            )
            whois_query = c.fetchall()
        if whois_query != []:
            result = {}
            for idx, field in enumerate(fields):
                result[field] = whois_query[0][idx]
            return result
        else:
            # Not found in the database
            # whois_query = subfinder.scan(domain, active_scan_status=False)
            whois_query = whois_scan.get_whois_data(domain)
            if whois_query != []:
                # Add whois query to the database in background
                t = threading.Thread(
                    target=db.add_whois_records,
                    args=({domain: whois_query}, conn, c)
                )
                t.start()
                result = {}
                for idx, field in enumerate(fields):
                    result[field] = whois_query[field]
                return result
            else:
                return []


class Subdomains(Resource):
    def get(self, domain):
        with conn:
            c.execute("SELECT subdomain FROM Subdomains where domain = %s", (domain,))
            subdomains = c.fetchall()
        if subdomains != []:
            subdomains = [subdomain[0] for subdomain in subdomains]
            return subdomains
        else:
            # Not found in the database
            subdomains = subfinder.scan(domain, active_scan_status=False)
            # Add subdomains to the database in background
            t = threading.Thread(
                target=db.add_subdomain_records,
                args=({domain: subdomains}, conn, c),
            )
            t.start()
            return subdomains
