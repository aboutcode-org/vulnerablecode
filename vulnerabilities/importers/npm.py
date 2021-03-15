# Author: Navonil Das (@NavonilDas)
# Copyright (c) nexB Inc. and others. All rights reserved.
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
#  VulnerableCode is a free software from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import asyncio
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
from vulnerabilities.data_source import GitDataSource
from vulnerabilities.data_source import Reference
from vulnerabilities.package_managers import NpmVersionAPI
from vulnerabilities.helpers import load_json

NPM_URL = "https://registry.npmjs.org{}"


class NpmDataSource(GitDataSource):
    def __enter__(self):
        super(NpmDataSource, self).__enter__()
        if not getattr(self, "_added_files", None):
            self._added_files, self._updated_files = self.file_changes(
                recursive=True, file_ext="json", subdir="./vuln/npm"
            )

        self._versions = NpmVersionAPI()
        self.set_api(self.collect_packages())

    def updated_advisories(self) -> Set[Advisory]:
        files = self._updated_files.union(self._added_files)
        advisories = []
        for f in files:
            processed_data = self.process_file(f)
            if processed_data:
                advisories.extend(processed_data)
        return self.batch_advisories(advisories)

    def set_api(self, packages):
        asyncio.run(self._versions.load_api(packages))

    def collect_packages(self):
        packages = set()
        files = self._updated_files.union(self._added_files)
        for f in files:
            data = load_json(f)
            packages.add(data["module_name"].strip())

        return packages

    @property
    def versions(self):  # quick hack to make it patchable
        return self._versions

    def process_file(self, file) -> List[Advisory]:

        record = load_json(file)
        advisories = []
        package_name = record["module_name"].strip()
        all_versions = self.versions.get(package_name)
        aff_range = record.get("vulnerable_versions", "")
        fixed_range = record.get("patched_versions", "")

        impacted_versions, resolved_versions = categorize_versions(
            all_versions, aff_range, fixed_range
        )

        impacted_purls = _versions_to_purls(package_name, impacted_versions)
        resolved_purls = _versions_to_purls(package_name, resolved_versions)
        vuln_reference = [
            Reference(
                url=NPM_URL.format(f'/-/npm/v1/advisories/{record["id"]}'),
                reference_id=record["id"],
            )
        ]

        for cve_id in record.get("cves") or [""]:
            advisories.append(
                Advisory(
                    summary=record.get("overview", ""),
                    vulnerability_id=cve_id,
                    impacted_package_urls=impacted_purls,
                    resolved_package_urls=resolved_purls,
                    references=vuln_reference,
                )
            )
        return advisories


def _versions_to_purls(package_name, versions):
    purls = {f"pkg:npm/{quote(package_name)}@{v}" for v in versions}
    return {PackageURL.from_string(s) for s in purls}


def categorize_versions(
    all_versions: Set[str],
    affected_version_range: str,
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

    aff_spec = RangeSpecifier(affected_version_range)
    fix_spec = RangeSpecifier(fixed_version_range)
    aff_ver, fix_ver = set(), set()

    # Unaffected version is that version which is in the fixed_version_range
    # or which is absent in the affected_version_range
    for ver in all_versions:
        if ver in fix_spec or ver not in aff_spec:
            fix_ver.add(ver)
        else:
            aff_ver.add(ver)

    return aff_ver, fix_ver
