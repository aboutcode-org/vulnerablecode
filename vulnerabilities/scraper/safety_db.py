# Data Imported from https://github.com/pyupio/safety-db
import json
from urllib.error import HTTPError
from urllib.request import urlopen
from dephell_specifier import RangeSpecifier

URL = 'https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json'


def get_data_file():
    with urlopen(URL) as file:
        json_file = json.load(file)
    return json_file


def get_all_versions_of_package(package_name):
    url = "https://pypi.org/pypi/{}/json".format(package_name)
    releases = set()
    try:
        with urlopen(url) as response:
            json_file = json.load(response)
    except HTTPError:  # PyPi does not have data about this package, we skip these
        return releases
    for release in json_file['releases']:
        releases.add(release)
    return releases


def import_vulnerabilities():
    vulnerability_package_dicts = []
    data = get_data_file()
    cves = set()
    for package_name in data:
        all_package_versions = set(get_all_versions_of_package(package_name))
        if len(all_package_versions) == 0:
            # PyPi does not have data about this package, we skip these
            continue
        for advisory in data[package_name]:
            description = advisory['advisory']
            cve_id = advisory.get('cve')
            vuln_id = advisory['id']
            vuln_version_ranges = advisory['specs']
            for vuln_version_range in vuln_version_ranges:
                version_range = RangeSpecifier(vuln_version_range)
                affected_versions = set()
                for version in all_package_versions:
                    if version in version_range:
                        affected_versions.add(version)
            unaffected_versions = all_package_versions - affected_versions
            if cve_id not in cves:
                # This data has duplicates hence the check
                vulnerability_package_dicts.append({
                    'package_name': package_name,
                    'vuln_id': vuln_id,
                    'affected_versions': affected_versions,
                    'unaffected_versions': unaffected_versions,
                    'cve_id': cve_id,
                    'description': description
                })
                cves.add(cve_id)
    return vulnerability_package_dicts
