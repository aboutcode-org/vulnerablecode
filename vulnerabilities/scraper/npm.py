# Author: Navonil Das (@NavonilDas)
# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import json
from dephell_specifier import RangeSpecifier
from urllib.request import urlopen
from urllib.error import HTTPError


NPM_URL = 'https://registry.npmjs.org{}'
PAGE = '/-/npm/v1/security/advisories?page=0'


def get_all_versions(package_name):
    """
    Returns all versions available for a module
    """
    package_name = package_name.strip()
    package_url = NPM_URL.format(f'/{package_name}')
    try:
        with urlopen(package_url) as response:
            data = json.load(response)
    except HTTPError as e:
        if e.code == 404:
            return []
        else:
            raise
        # NPM registry has no data regarding this package, we skip these
    return [v for v in data.get('versions', {})]


def extract_versions(package_name, aff_version_range, fixed_version_range):
    """
    Seperate list of affected versions and unaffected versions from all versions
    using the ranges specified.
    """
    aff_spec = RangeSpecifier(aff_version_range)
    fix_spec = RangeSpecifier(fixed_version_range)
    all_ver = get_all_versions(package_name)
    if all_ver == []:
        # NPM registry has no data regarding this package, we skip these
        return ([], [])
    aff_ver = []
    fix_ver = []
    # Unaffected version is that version which  is in the fixed_version_range
    # or which is absent in the aff_version_range
    for ver in all_ver:
        if ver in fix_spec or ver not in aff_spec:
            fix_ver.append(ver)
        else:
            aff_ver.append(ver)
    return (aff_ver, fix_ver)


def extract_data(JSON):
    """
    Extract package name, summary, CVE IDs, severity and
    fixed & affected versions
    """
    package_vulnerabilities = []
    for obj in JSON.get('objects', []):
        if 'module_name' not in obj:
            continue

        package_name = obj['module_name']

        affected_versions, fixed_versions = extract_versions(
            package_name,
            obj.get('vulnerable_versions', ''),
            obj.get('patched_versions', '')
        )
        if affected_versions == fixed_versions == []:
            continue
            # NPM registry has no data regarding this package finally we skip these

        package_vulnerabilities.append({
            'package_name': package_name,
            'summary': obj.get('overview', ''),
            'cve_ids': obj.get('cves', []),
            'fixed_versions': fixed_versions,
            'affected_versions': affected_versions,
            'severity': obj.get('severity', ''),
            'advisory': obj.get('url', ''),
        })
    return package_vulnerabilities


def scrape_vulnerabilities():
    """
    Extract JSON From NPM registry
    """
    package_vulnerabilities = []
    nextpage = PAGE
    while nextpage:
        try:
            cururl = NPM_URL.format(nextpage)
            response = json.load(urlopen(cururl))
            package_vulnerabilities.extend(extract_data(response))
            nextpage = response.get('urls', {}).get('next')

        except HTTPError as error:
            if error.code == 404:
                break
            else:
                raise

    return package_vulnerabilities
