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

import yaml
import re
import json
import requests
from typing import Set
from typing import List

from packageurl import PackageURL

from vulnerabilities.data_source import GitDataSource
from vulnerabilities.data_source import GitDataSourceConfiguration
from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import Reference


class ElixirSecurityDataSource(GitDataSource):
    def __enter__(self):
        super(ElixirSecurityDataSource, self).__enter__()

        if not getattr(self, "_added_files", None):
            self._added_files, self._updated_files = self.file_changes(
                recursive=True, file_ext="yml", subdir="./packages"
            )

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

    @staticmethod
    def generate_all_versions_list(pkg_name):
        resp = requests.get(f"https://hex.pm/api/packages/{pkg_name}")
        resp = resp.content
        json_resp = json.loads(resp)
        versions_list = []
        for release in json_resp["releases"]:
            versions_list.append(release["version"])
        return versions_list

    def get_pkg_from_range(self, versions_list, pkg_name):
        pkg_versions = []
        all_versions_list = self.generate_all_versions_list(pkg_name)
        if versions_list is None:
            return
        for version in versions_list:
            if re.match("^>=", version):
                index = all_versions_list.index(version[3:])
                pkg_versions = pkg_versions + all_versions_list[0: index + 1]
            elif re.match("^>", version):
                index = all_versions_list.index(version[2:])
                pkg_versions = pkg_versions + all_versions_list[0:index]
            elif re.match("^<", version):
                index = all_versions_list.index(version[2:])
                pkg_versions = pkg_versions + all_versions_list[index + 1: -1]
            else:
                pkg_versions.append(version[3:])
        return pkg_versions

    def process_file(self, path):
        with open(path) as f:
            yaml_file = yaml.safe_load(f)
            pkg_name = yaml_file["package"]
            safe_pkg_versions = []
            if yaml_file.get("unaffected_versions"):
                safe_pkg_versions = self.get_pkg_from_range(
                    yaml_file["patched_versions"] + yaml_file["unaffected_versions"],
                    pkg_name,
                )
            else:
                safe_pkg_versions = self.get_pkg_from_range(
                    yaml_file["patched_versions"], pkg_name
                )
            cve_id = yaml_file["cve"]
            safe_purls = []
            if safe_pkg_versions is not None:
                safe_purls = {
                    PackageURL(name=pkg_name, type="hex", version=version)
                    for version in safe_pkg_versions
                }

            vuln_reference = [
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
