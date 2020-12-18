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
#  VulnerableCode is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import asyncio
from typing import List, Set

import yaml
from dephell_specifier import RangeSpecifier
from packageurl import PackageURL

from vulnerabilities.data_source import GitDataSource
from vulnerabilities.data_source import GitDataSourceConfiguration
from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import Reference
from vulnerabilities.package_managers import HexVersionAPI


class ElixirSecurityDataSource(GitDataSource):
    def __enter__(self):
        super(ElixirSecurityDataSource, self).__enter__()

        if not getattr(self, "_added_files", None):
            self._added_files, self._updated_files = self.file_changes(
                recursive=True, file_ext="yml", subdir="./packages"
            )
        self.pkg_manager_api = HexVersionAPI()
        self.set_api(self.collect_packages())

    def set_api(self, packages):
        asyncio.run(self.pkg_manager_api.load_api(packages))

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

    def collect_packages(self):
        packages = set()
        files = self._updated_files.union(self._added_files)
        for f in files:
            data = load_yaml(f)
            if data.get("package"):
                packages.add(data["package"])

        return packages

    def get_versions_from_range(self, version_list, pkg_name):
        pkg_versions = []
        if not getattr(self, 'pkg_manager_api', None):
            self.pkg_manager_api = HexVersionAPI()
        all_version_list = self.pkg_manager_api.get(
            pkg_name)
        if version_list is None:
            return
        version_ranges = {RangeSpecifier(r) for r in version_list}
        for version in all_version_list:
            if any([version in v for v in version_ranges]):
                pkg_versions.append(version)
        return pkg_versions

    def process_file(self, path):
        yaml_file = load_yaml(path)
        pkg_name = yaml_file["package"]
        safe_pkg_versions = []
        if yaml_file.get("unaffected_versions"):
            safe_pkg_versions = self.get_versions_from_range(
                yaml_file["patched_versions"] +
                yaml_file["unaffected_versions"],
                pkg_name,
            )
        else:
            safe_pkg_versions = self.get_versions_from_range(
                yaml_file["patched_versions"], pkg_name
            )
        if yaml_file.get('cve'):
            cve_id = "CVE-" + yaml_file["cve"]
        else:
            cve_id = ""

        safe_purls = []
        if safe_pkg_versions is not None:
            safe_purls = {
                PackageURL(name=pkg_name, type="hex", version=version)
                for version in safe_pkg_versions
            }

        vuln_reference = [
            Reference(
                reference_id=yaml_file["id"],
            ),
            Reference(
                url=yaml_file["link"],
            )
        ]

        return Advisory(
            summary=yaml_file["description"],
            impacted_package_urls=[],
            resolved_package_urls=safe_purls,
            cve_id=cve_id,
            vuln_references=vuln_reference,
        )


def load_yaml(path):
    with open(path) as f:
        return yaml.safe_load(f)
