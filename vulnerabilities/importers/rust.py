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
from itertools import chain
from typing import Optional, Mapping
from typing import Set
from typing import Tuple
from urllib.error import HTTPError
from urllib.request import urlopen

import pytoml as toml
from dephell_specifier import RangeSpecifier
from packageurl import PackageURL

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import GitDataSource
from vulnerabilities.data_source import VulnerabilityReferenceUnit


class RustDataSource(GitDataSource):

    def __enter__(self):
        super(RustDataSource, self).__enter__()

        if not getattr(self, '_added_files', None):
            self._added_files, self._updated_files = self.file_changes(
                subdir='crates',  # TODO Consider importing the advisories for cargo, etc as well.
                recursive=True,
                file_ext='toml',
            )

    @property
    def crates_api(self):
        if not hasattr(self, '_crates_api'):
            setattr(self, '_crates_api', VersionAPI())
        return self._crates_api

    def added_advisories(self) -> Set[Advisory]:
        return self._load_advisories(self._added_files)

    def updated_advisories(self) -> Set[Advisory]:
        return self._load_advisories(self._updated_files)

    def _load_advisories(self, files) -> Set[Advisory]:
        files = [f for f in files if not f.endswith('-0000.toml')]  # skip temporary files

        while files:
            batch, files = files[:self.batch_size], files[self.batch_size:]

            advisories = set()

            for path in batch:
                advisory = self._load_advisory(path)
                if advisory:
                    advisories.add(advisory)
            yield advisories

    def _load_advisory(self, path: str) -> Optional[Advisory]:
        with open(path) as f:
            record = toml.load(f)
            advisory = record.get('advisory', {})

        references = []
        crate_name = advisory['package']
        if advisory.get('url'):
            references.append(VulnerabilityReferenceUnit(
                url=advisory['url']
            ))

        all_versions = self.crates_api.get(crate_name)

        affected_ranges = {RangeSpecifier(r) for r
                           in chain.from_iterable(
                record.get('affected', {}).get('functions', {}).values())}

        unaffected_ranges = {RangeSpecifier(r) for r
                             in record.get('versions', {}).get('unaffected', [])}
        resolved_ranges = {RangeSpecifier(r) for r
                           in record.get('versions', {}).get('patched', [])}

        unaffected, affected = categorize_versions(
            all_versions, unaffected_ranges, affected_ranges, resolved_ranges)

        impacted_purls = {PackageURL(type='cargo', name=crate_name, version=v) for v in affected}
        resolved_purls = {PackageURL(type='cargo', name=crate_name, version=v) for v in unaffected}

        cve_id = None
        if 'aliases' in advisory:
            for alias in advisory['aliases']:
                if alias.startswith('CVE-'):
                    cve_id = alias
                    break
        

        references.append(VulnerabilityReferenceUnit(
                reference_id=advisory['id'],
                url='https://rustsec.org/advisories/{}.html'.format(advisory['id'])
            )
        )

        return Advisory(
            summary=advisory.get('description', ''),
            impacted_package_urls=impacted_purls,
            resolved_package_urls=resolved_purls,
            cve_id=cve_id,
            vuln_references=references
        )


def categorize_versions(
        all_versions: Set[str],
        unaffected_versions: Set[RangeSpecifier],
        affected_versions: Set[RangeSpecifier],
        resolved_versions: Set[RangeSpecifier],
) -> Tuple[Set[str], Set[str]]:
    """
    Categorize all versions of a crate according to the given version ranges.

    :return: unaffected versions, affected versions
    """
    unaffected, affected = set(), set()

    if not any(unaffected_versions.union(affected_versions).union(resolved_versions)):
        return unaffected, affected

    for version in all_versions:
        if affected_versions and all([version in av for av in affected_versions]):
            affected.add(version)
        elif unaffected_versions and all([version in av for av in unaffected_versions]):
            unaffected.add(version)
        elif resolved_versions and all([version in av for av in resolved_versions]):
            unaffected.add(version)

    # If some versions were not classified above, one or more of the given ranges might be empty, so
    # the remaining versions default to either affected or unaffected.
    uncategorized_versions = all_versions - unaffected.union(affected)
    if uncategorized_versions:
        if not affected_versions:
            affected.update(uncategorized_versions)
        else:
            unaffected.update(uncategorized_versions)

    return unaffected, affected


class VersionAPI:
    def __init__(self, cache: Mapping[str, Set[str]] = None):
        self.cache = cache or {}

    def get(self, package_name: str) -> Set[str]:
        package_name = package_name.strip()

        if package_name not in self.cache:
            releases = set()

            try:
                with urlopen(f'https://crates.io/api/v1/crates/{package_name}') as response:
                    response = json.load(response)
                    for version_info in response['versions']:
                        releases.add(version_info['num'])
            except HTTPError as e:
                if e.code == 404:
                    pass
                else:
                    raise

            self.cache[package_name] = releases

        return self.cache[package_name]
