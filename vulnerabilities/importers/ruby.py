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

from json import JSONDecodeError
from typing import Set
from typing import List

from dephell_specifier import RangeSpecifier
from dephell_specifier.range_specifier import InvalidSpecifier
from packageurl import PackageURL
import requests
import yaml

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import GitDataSource
from vulnerabilities.package_managers import RubyVersionAPI


class RubyDataSource(GitDataSource):

    def __enter__(self):
        super(RubyDataSource, self).__enter__()

        if not getattr(self, '_added_files', None):
            self._added_files, self._updated_files = self.file_changes(
                recursive=True, file_ext='yml', subdir='./gems')

    def updated_advisories(self) -> Set[Advisory]:
        files = self._updated_files
        advisories = []
        for f in files:
            processed_data = self.process_file(f)
            if processed_data:
                advisories.append(processed_data)
        return self.batch_advisories(advisories)

    def added_advisories(self) -> Set[Advisory]:
        files = self._added_files
        advisories = []
        for f in files:
            processed_data = self.process_file(f)
            if processed_data:
                advisories.append(processed_data)
        return self.batch_advisories(advisories)

    def process_file(self, path) -> List[Advisory]:
        with open(path) as f:
            record = yaml.safe_load(f)
            package_name = record.get(
                'gem')

            if not package_name:
                return

            if 'cve' in record:
                cve_id = 'CVE-{}'.format(record['cve'])
            else:
                return

            safe_version_ranges = record.get('patched_versions', [])
            # this case happens when the advisory contain only 'patched_versions' field
            # and it has value None(i.e it is empty :( ).
            if not safe_version_ranges:
                safe_version_ranges = []
            safe_version_ranges += record.get('unaffected_versions', [])
            safe_version_ranges = [i for i in safe_version_ranges if i]

            if not getattr(self, 'pkg_manager_api', None):
                self.pkg_manager_api = RubyVersionAPI()
            all_vers = self.pkg_manager_api.get_all_version_of_package(
                package_name)
            safe_versions, affected_versions = self.categorize_versions(
                all_vers, safe_version_ranges)

            impacted_purls = {
                PackageURL(
                    name=package_name,
                    type='gem',
                    version=version,
                ) for version in affected_versions}

            resolved_purls = {
                PackageURL(
                    name=package_name,
                    type='gem',
                    version=version,
                ) for version in safe_versions}

            return Advisory(
                summary=record.get('description', ''),
                impacted_package_urls=impacted_purls,
                resolved_package_urls=resolved_purls,
                reference_urls=[record.get('url', '')],
                cve_id=cve_id
            )

    @staticmethod
    def categorize_versions(all_versions, unaffected_version_ranges):

        for id, elem in enumerate(unaffected_version_ranges):
            try:
                unaffected_version_ranges[id] = RangeSpecifier(
                    elem.replace(' ', ''))
            except InvalidSpecifier:
                continue

        safe_versions = set()
        for i in all_versions:
            for ver_rng in unaffected_version_ranges:

                if i in ver_rng:

                    safe_versions.add(i)

        return (safe_versions, all_versions-safe_versions)
