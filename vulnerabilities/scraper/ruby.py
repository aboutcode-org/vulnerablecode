import os
import urllib.request
from urllib.error import HTTPError
from zipfile import ZipFile
from io import BytesIO
import saneyaml
from dephell_specifier import RangeSpecifier
from urllib.request import urlopen

RUBYSEC_DB_URL = 'https://github.com/rubysec/ruby-advisory-db/archive/master.zip'


def rubygem_advisories(url, prefix='ruby-advisory-db-master/gems/'):
    with urlopen(url) as response:
        with ZipFile(BytesIO(response.read())) as zf:
            for path in zf.namelist():
                if path.startswith(prefix) and path.endswith('.yml'):
                    yield saneyaml.load(zf.open(path))


def get_all_versions_of_package(package_name):
    url_to_load = 'https://rubygems.org/api/v1/versions/' + package_name + '.yaml'
    try:
        page = urllib.request.urlopen(url_to_load)
        package_history = saneyaml.load(page)
    except HTTPError:
        return []
    for version in package_history:
        yield version['number']


def get_patched_range(spec_list):
    spec_list = [string.replace(' ', '') for string in spec_list]
    for spec in spec_list:
        if 'rc' in spec:
            continue
        yield RangeSpecifier(spec)


def load_vulnerability_package(vulnerability):
    package_name = vulnerability.get(
        'gem')

    if not package_name:
        return

    if 'cve' in vulnerability:
        vulnerability_id = 'CVE-{}'.format(vulnerability['cve'])
    else:
        return

    advisory_url = vulnerability.get('url')
    patched_version_ranges = list(
        get_patched_range(
            vulnerability.get('patched_versions', [])))
    all_versions = set(get_all_versions_of_package(package_name))
    unaffected_versions = set()

    if patched_version_ranges:
        for version in all_versions:
            for spec in patched_version_ranges:
                if version in spec:
                    unaffected_versions.add(version)
                    break

    affected_versions = all_versions - unaffected_versions

    return {
        'package_name': package_name,
        'cve_id': vulnerability_id,
        'fixed_versions': unaffected_versions,
        'affected_versions': affected_versions,
        'advisory': advisory_url
    }


def import_vulnerabilities():
    vulnerability_package_dicts = []
    for vulnerability in rubygem_advisories(RUBYSEC_DB_URL):
        package = load_vulnerability_package(vulnerability)
        if package:
            vulnerability_package_dicts.append(package)

    return vulnerability_package_dicts
