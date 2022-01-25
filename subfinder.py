import json
from pprint import pprint
import requests
from bs4 import BeautifulSoup
from typing import Iterable
import yaml

from utils import get_random_user_agent, get_domain, read_file, unique_list


CONFIG_FILE = "config.yaml"


def crtsh(domain: str, print=print) -> list:
    # Reference: https://github.com/YashGoti/crtsh/blob/master/crtsh.py
    BASE_URL = "https://crt.sh/?q={}&output=json"
    try:
        r = requests.get(BASE_URL.format(domain))
        data = r.json()
    except:
        print("There is an error while getting subdomains via crtsh.")
        return []
    found = list()
    for i in data:
        name_value: str = i.get("name_value")
        subname_value = name_value.split("\n")
        for sub in subname_value:
            if sub == domain:
                continue
            if sub.startswith("*.") and sub.replace("*.", "") != domain:
                found.append(sub.replace("*.", ""))
            elif not sub.startswith("*") and sub.endswith(domain):
                found.append(sub)
    return unique_list(found)


def dnsdumpster(domain: str, print=print) -> list:
    URL = "https://dnsdumpster.com:443/"
    try:
        r = requests.get(URL, headers={"User-Agent": get_random_user_agent()})
        soup = BeautifulSoup(r.text, "html.parser")
        text = soup.select_one("form input[name='csrfmiddlewaretoken']")

        csrfmiddlewaretoken = text.get("value")
        csrftoken = r.cookies.get("csrftoken")

        cookies = {"csrftoken": csrftoken}
        headers = {
            "User-Agent": get_random_user_agent(),
            "Origin": "https://dnsdumpster.com",
            "Referer": "https://dnsdumpster.com/",
        }
        data = {
            "csrfmiddlewaretoken": csrfmiddlewaretoken,
            "targetip": domain,
            "user": "free",
        }
        try:
            r = requests.post(URL, headers=headers, cookies=cookies, data=data)
            soup = BeautifulSoup(r.text, "html.parser")
        except:
            print("There is an error while getting subdomains via dnsdumpster.")
            return []
        soup = soup.select_one("div.table-responsive:last-child")

        found_subdomains = []
        for td in soup.find_all("td", attrs={"class": "col-md-4"}):
            if isinstance(td.text, str):
                sub = td.text.split()[0]
                if sub == domain:
                    continue
                found_subdomains.append(sub)
            else:
                print("---")
                print("THERE IS A PROBLEM")
                print("---")
        r.close()

        return unique_list(found_subdomains)
    except:
        print("There is an error while getting subdomains via dnsdumpster.")
        return []


def threadcrowd(domain: str, print=print) -> list:
    URL = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    try:
        r = requests.get(URL, headers={"User-Agent": get_random_user_agent()})
        data = r.json()
        found = []

        subdomains: list = data.get("subdomains")
        for sub in subdomains:
            if sub == domain:
                continue
            found.append(sub)

        return unique_list(found)
    except:
        print("There is an error while getting subdomains via threadcrowd.")
        return []


def brute(domain: str, fuzsubdomains: Iterable[str]) -> list:
    found = []
    for fuzsub in fuzsubdomains:
        url = f"https://{fuzsub}.{domain}"
        try:
            requests.get(
                url, headers={"User-Agent": get_random_user_agent()}, timeout=10
            )
        except requests.ConnectionError:
            continue
        except Exception:
            pass
        found.append(f"{fuzsub}.{domain}")
    return unique_list(found)


supported_engines = {
    "crtsh": crtsh,
    "dnsdumpster": dnsdumpster,
    "threadcrowd": threadcrowd,
}


def scan(
    domain,
    fuzsubdomains=None,
    chosen_engines=supported_engines.values(),
    passive_scan_status=True,
    active_scan_status=True,
    print=print,
) -> list:
    found_subdomains = []
    if passive_scan_status:
        for chosen_engine in chosen_engines:
            found = chosen_engine(domain, print=print)
            for subdomain in found:
                found_subdomains.append(subdomain)

    if active_scan_status:
        brute_subdomains = brute(domain, fuzsubdomains)
        for subdomain in brute_subdomains:
            found_subdomains.append(subdomain)
    return unique_list(found_subdomains)


def write_output(result, output_file, output_file_format, print=pprint):
    if output_file:
        if output_file_format.lower() == "json":
            with open(f"{output_file}.{output_file_format}", "w") as f:
                json.dump(result, f, indent=4)
        elif (
            output_file_format.lower() == "yaml" or output_file_format.lower() == "yml"
        ):
            with open(f"{output_file}.{output_file_format}", "w") as f:
                yaml.safe_dump(result, f)
        else:
            # unknown file format request
            print(result)
    else:
        print(result)


def main(config_file: str, no_print: bool = False):
    if no_print:

        def _print(*args, **kwargs):
            pass

        pprint = _print
    else:
        _print = print

    with open(config_file, "rb") as f:
        config: dict = yaml.safe_load(f)

    exclude_comments = config.get("exclude-comments")

    domain_file = config.get("domain-file")
    domain = config.get("domain")
    if domain_file == None and domain == None:
        _print("No domain or domain file is specified, exiting...")
        exit()
    elif domain_file == None:
        domains = [domain]
    else:
        domains = read_file(
            domain_file, ext=get_domain, exclude_comments=exclude_comments
        )

    try:
        active_scan_status = config["scan"]["active"].get("status")
    except:
        active_scan_status = True

    try:
        passive_scan_status = config["scan"]["passive"].get("status")
    except:
        passive_scan_status = True

    subdomain_file = config.get("subdomain-file")
    fuzsubdomains = None
    if subdomain_file == None and active_scan_status:
        _print("No subdomain file is specified, exiting...")
        exit()
    elif subdomain_file != None:
        fuzsubdomains = read_file(subdomain_file)

    chosen_engines = []

    try:
        _engines = config["scan"]["passive"].get("engines")
        for _engine in _engines:
            _engine: str = _engine.lower()
            if _engine in supported_engines:
                chosen_engines.append(supported_engines[_engine])
    except:
        if passive_scan_status:
            _print("No engine is specified, using default engines")
        chosen_engines = list(supported_engines.values())

    output_file = config.get("output-file")
    if not output_file:
        _print(
            "No output file is specified, the results will be printed out to the console."
        )

    output_file_format = config.get("output-file-format")
    if not output_file_format:
        output_file_format = "json"

    result = {}
    for domain in domains:
        found_subdomains = []
        for subdomain in scan(
            domain=domain,
            fuzsubdomains=fuzsubdomains,
            chosen_engines=chosen_engines,
            passive_scan_status=passive_scan_status,
            active_scan_status=active_scan_status,
            print=_print,
        ):
            found_subdomains.append(subdomain)

        result[domain] = unique_list(found_subdomains)

    write_output(result, output_file, output_file_format, print=_print)


if __name__ == "__main__":
    main(config_file=CONFIG_FILE)
