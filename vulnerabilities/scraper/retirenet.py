import json
import re
from urllib.request import urlopen
from urllib.error import HTTPError

cve_regex = re.compile(r"CVE-\d+-\d+")
URL = "https://raw.githubusercontent.com/RetireNet/Packages/master/Content/{}.json"

# TODO: GitHub uses Etags, utilise it to reduce duplicate work


def get_json_files():
    id = 1
    curr_url = URL.format(id)
    try:
        while urlopen(curr_url):
            id += 1
            yield json.load(urlopen(curr_url))
            curr_url = URL.format(id)
    except HTTPError as err:
        if err.code == 404:
            pass
            # At this point, we have viewed all the json files
        else:
            raise HTTPError


def vuln_id_from_desc(desc):
    res = cve_regex.search(desc)
    if res:
        return desc[res.start():res.end()]
    else:
        return None


def import_vulnerabilities():
    vulnerability_package_dicts = []
    for advisory in get_json_files():
        if vuln_id_from_desc(advisory["description"]):
            vuln_id = vuln_id_from_desc(advisory["description"])
        else:
            continue
        vulnerability_package_dicts.append(
            {
                "vuln_id": vuln_id,
                "pkg_info": advisory["packages"]
            }
        )
