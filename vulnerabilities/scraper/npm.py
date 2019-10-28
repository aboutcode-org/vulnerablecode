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
import re
import semantic_version
from urllib.request import urlopen

NPM_URL = 'https://registry.npmjs.org{}'
PAGE = '/-/npm/v1/security/advisories?page=1'


def remove_spaces(x):
    """
    Remove Multiple Space, spaces after relational operator
    and remove v charecter in front of version string (ex v1.2.3) 
    """

    x = re.sub(r' +', ' ', x)
    x = re.sub(r'< +', '<', x)
    x = re.sub(r'> +', '>', x)
    x = re.sub(r'<= +', '<=', x)
    x = re.sub(r'>= +', '>=', x)
    x = re.sub(r'>=[vV]', '>=', x)
    x = re.sub(r'<=[vV]', '<=', x)
    x = re.sub(r'>[vV]', '>', x)
    x = re.sub(r'<[vV]', '<', x)
    return x


def get_all_version(package_name):
    """
    Returns all available for a module
    """
    
    package_url = NPM_URL.format('/'+package_name)
    response = urlopen(package_url).read()
    data = json.loads(response)
    versions = data.get('versions', {})
    all_version = [obj for obj in versions]
    return all_version


def extract_version(package_name, aff_version_range, fixed_version_range):
    """
    Seperate list of Affected version and fixed version from all version
    using the range specified
    """

    if aff_version_range == '' or fixed_version_range == '':
        return ([], [])

    aff_spec = semantic_version.NpmSpec(remove_spaces(aff_version_range))
    fix_spec = semantic_version.NpmSpec(remove_spaces(fixed_version_range))
    all_ver = get_all_version(package_name)
    aff_ver = []
    fix_ver = []
    for ver in all_ver:
        cur_version = semantic_version.Version(ver)
        if cur_version in aff_spec:
            aff_ver.append(ver)
        else:
            if cur_version in fix_spec:
                fix_ver.append(ver)

    return (aff_ver, fix_ver)


def extract_data(JSON):
    """
    Extract module name, summary, vulnerability id,severity
    """
    package_vulnerabilities = []
    for obj in JSON.get('objects', []):
        if 'module_name' not in obj:
            continue
        package_name = obj['module_name']
        summary = obj.get('overview', '')
        severity = obj.get('severity', '')

        vulnerability_id = obj.get('cves', [])
        if len(vulnerability_id) > 0:
            vulnerability_id = vulnerability_id[0]
        else:
            vulnerability_id = ''

        affected_version, fixed_version = extract_version(
            package_name,
            obj.get('vulnerable_versions', ''),
            obj.get('patched_versions', '')
        )

        package_vulnerabilities.append({
            'package_name': package_name,
            'summary': summary,
            'vulnerability_id': vulnerability_id,
            'fixed_version': fixed_version,
            'affected_version': affected_version,
            'severity': severity
        })
    return package_vulnerabilities


def scrape_vulnerabilities():
    """
    Extract JSON From NPM registry
    """
    cururl = NPM_URL.format(PAGE)
    response = urlopen(cururl).read()
    package_vulnerabilities = []
    while True:
        data = json.loads(response)
        package_vulnerabilities = package_vulnerabilities + extract_data(data)
        next_page = data.get('urls', {}).get('next', False)
        if next_page:
            cururl = NPM_URL.format(next_page)
            response = urlopen(cururl).read()
        else:
            break
    return package_vulnerabilities
