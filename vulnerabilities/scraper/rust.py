from io import BytesIO
import json

from dephell_specifier import RangeSpecifier
import pytoml as toml
from urllib.request import urlopen
import urllib.request
from urllib.error import HTTPError
from zipfile import ZipFile


RUSTSEC_DB_URL = 'https://github.com/RustSec/advisory-db/archive/master.zip'


def rust_crate_advisories(url, prefix='advisory-db-master/crates/'):
    with urlopen(url) as response:
        with ZipFile(BytesIO(response.read())) as zf:
            for path in zf.namelist():
                if path.startswith(prefix) and path.endswith('.toml'):
                    yield toml.load(zf.open(path))


def all_versions_of_crate(crate):
    info_url = "https://crates.io/api/v1/crates/{}".format(crate)
    with urlopen(info_url) as info:
        info = json.load(info)
        for version_info in info['versions']:
            yield version_info['num']


def import_vulnerabilities():

    vulnerability_package_dicts = []
    for advisory in rust_crate_advisories(RUSTSEC_DB_URL):

        affected_version_range_lists = list(advisory.get(
            'affected', {}).get('functions', {}).values())
        unaffected_version_range_list = advisory['versions'].get(
            'unaffected', [])

        patched_version_range_list = advisory['versions']['patched']
        # FIXME: Make distinction between unaffected and patched packages
        # Check https://github.com/nexB/vulnerablecode/issues/144
        unaffected_version_range_list += patched_version_range_list

        have_unaffected_version_range = len(unaffected_version_range_list) != 0
        have_affected_version_range = len(affected_version_range_lists) != 0

        if not (have_affected_version_range or have_unaffected_version_range):
            continue

        vuln_id = advisory['advisory']['id']
        crate_name = advisory['advisory']['package']
        description = advisory['advisory']['description']
        reference = advisory['advisory'].get('url', '')

        all_versions = set(all_versions_of_crate(crate_name))
        affected_versions = set()
        unaffected_versions = set()

        for version in all_versions:
            categorised = False
            for affected_version_range_list in affected_version_range_lists:
                for affected_version_range in affected_version_range_list:
                    affected_version_range = RangeSpecifier(
                        affected_version_range)
                    if version in affected_version_range:
                        affected_versions.add(version)
                        categorised = True
                        break

            if have_unaffected_version_range and not categorised:
                for unaffected_version_range in unaffected_version_range_list:
                    if version in RangeSpecifier(unaffected_version_range):
                        unaffected_versions.add(version)
                        break

        if not have_unaffected_version_range:
            unaffected_versions = all_versions - affected_versions

        elif not have_affected_version_range:
            affected_versions = all_versions - unaffected_versions

        vulnerability_package_dicts.append({
            'package_name': crate_name,
            'vuln_id': vuln_id,
            'fixed_versions': unaffected_versions,
            'affected_versions': affected_versions,
            'advisory': reference,
            'description': description
        })

    return vulnerability_package_dicts
