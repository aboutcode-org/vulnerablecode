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
from typing import Any
from typing import List
from typing import Mapping
from typing import Set
from typing import Tuple
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import urlopen

from dateutil.parser import parse
from dephell_specifier import RangeSpecifier
from packageurl import PackageURL

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.package_managers import NpmVersionAPI

NPM_URL = 'https://registry.npmjs.org{}'
PAGE = '/-/npm/v1/security/advisories?perPage=100&page=0'


class NpmDataSource(DataSource):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._api_response = None
        self._versions = NpmVersionAPI()
        self._added_records, self._updated_records = [], []
        self._added_advisories, self._updated_advisories = [], []

    def __enter__(self):
        self._api_response = self._fetch()
        self._categorize_records()

    @property
    def versions(self):  # quick hack to make it patchable
        return self._versions

    def _fetch(self) -> Mapping[str, Any]:
        data = None
        nextpage = PAGE
        while nextpage:
            try:
                with urlopen(NPM_URL.format(nextpage)) as response:
                    response = json.load(response)

                    if data is None:
                        data = response
                    else:
                        data['objects'].extend(response.get('objects', []))

                nextpage = response.get('urls', {}).get('next')

            except HTTPError as error:
                if error.code == 404:
                    return data
                else:
                    raise

        return data

    def _categorize_records(self) -> None:
        for advisory in self._api_response['objects']:
            created = parse(advisory['created']).timestamp()
            updated = parse(advisory['updated']).timestamp()

            if created > self.cutoff_timestamp:
                self._added_records.append(advisory)
            elif updated > self.cutoff_timestamp:
                self._updated_records.append(advisory)

    def _parse(self, records: List[Mapping[str, Any]]) -> List[Advisory]:
        advisories = []

        for record in records:
            package_name = record['module_name']
            all_versions = self.versions.get(package_name)
            aff_range = record.get('vulnerable_versions', '')
            fixed_range = record.get('patched_versions', '')

            impacted_versions, resolved_versions = categorize_versions(
                all_versions,
                aff_range,
                fixed_range
            )

            impacted_purls = _versions_to_purls(package_name, impacted_versions)
            resolved_purls = _versions_to_purls(package_name, resolved_versions)

            for cve_id in record.get('cves') or ['']:
                advisories.append(Advisory(
                    summary=record.get('overview', ''),
                    cve_id=cve_id,
                    impacted_package_urls=impacted_purls,
                    resolved_package_urls=resolved_purls,
                    reference_urls=[NPM_URL.format(f'/-/npm/v1/advisories/{record["id"]}')],
                ))

        return advisories

    def added_advisories(self) -> Set[Advisory]:
        return self.batch_advisories(self._parse(self._added_records))

    def updated_advisories(self) -> Set[Advisory]:
        return self.batch_advisories(self._parse(self._updated_records))


def _versions_to_purls(package_name, versions):
    purls = {f'pkg:npm/{quote(package_name)}@{v}' for v in versions}
    return {PackageURL.from_string(s) for s in purls}


def categorize_versions(
        all_versions: Set[str],
        aff_version_range: str,
        fixed_version_range: str,
) -> Tuple[Set[str], Set[str]]:
    """
    Seperate list of affected versions and unaffected versions from all versions
    using the ranges specified.

    :return: impacted, resolved versions
    """
    if not all_versions:
        # NPM registry has no data regarding this package, we skip these
        return set(), set()

    aff_spec = RangeSpecifier(aff_version_range)
    fix_spec = RangeSpecifier(fixed_version_range)
    aff_ver, fix_ver = set(), set()

    # Unaffected version is that version which is in the fixed_version_range
    # or which is absent in the aff_version_range
    for ver in all_versions:
        if ver in fix_spec or ver not in aff_spec:
            fix_ver.add(ver)
        else:
            aff_ver.add(ver)

    return aff_ver, fix_ver
