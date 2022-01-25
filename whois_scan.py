import json
from whois import whois
from pprint import pprint
import yaml
from typing import Tuple
from datetime import datetime

from utils import get_domain, read_file

CONFIG_FILE = "config-whois.yaml"


def get_whois_data(domain: str) -> Tuple[str, str, str]:
    w = whois(domain)
    creation_date: datetime = w.creation_date
    expiration_date: datetime = w.expiration_date
    registrar = w.registrar

    if isinstance(creation_date, list):
        creation_date = creation_date[0].strftime("%d.%m.%Y %H:%M:%S")
    else:
        creation_date = creation_date.strftime("%d.%m.%Y %H:%M:%S")
    if isinstance(expiration_date, list):
        expiration_date = expiration_date[0].strftime("%d.%m.%Y %H:%M:%S")
    else:
        expiration_date = expiration_date.strftime("%d.%m.%Y %H:%M:%S")

    data = {
        "registrar": registrar,
        "creation_date": creation_date,
        "expiration_date": expiration_date,
    }
    return data


def main(config_file: str):
    with open(config_file, "rb") as f:
        config: dict = yaml.safe_load(f)

    domain_file = config.get("domain-file")
    domain = config.get("domain")
    if domain_file == None and domain == None:
        print("No domain or domain file is specified, exiting...")
        exit()
    elif domain_file == None:
        domains = [domain]
    else:
        domains = read_file(domain_file, ext=get_domain)

    output_file = config.get("output-file")
    if not output_file:
        print(
            "No output file is specified, the results will be printed out to the console."
        )

    output_file_format = config.get("output-file-format")
    if not output_file_format:
        output_file_format = "json"

    result = {}
    for domain in domains:
        result[domain] = get_whois_data(domain)

    if output_file:
        if output_file_format.lower() == "json":
            with open(f"{output_file}.{output_file_format}", "w") as f:
                json.dump(result, f, indent=4)
        elif output_file_format.lower() == "yaml":
            with open(f"{output_file}.{output_file_format}", "w") as f:
                yaml.safe_dump(result, f)
        else:
            # unknown file format request
            pprint(result)
    else:
        pprint(result)


if __name__ == "__main__":
    main(config_file=CONFIG_FILE)
