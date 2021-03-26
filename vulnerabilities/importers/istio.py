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
import re
from typing import List, Set

import yaml

from dephell_specifier import RangeSpecifier
from packageurl import PackageURL
from vulnerabilities.data_source import Advisory, GitDataSource, Reference
from vulnerabilities.package_managers import GitHubTagsAPI

is_release = re.compile(r"^[\d.]+$", re.IGNORECASE).match


class IstioDataSource(GitDataSource):
    def __enter__(self):
        super(IstioDataSource, self).__enter__()

        if not getattr(self, "_added_files", None):
            self._added_files, self._updated_files = self.file_changes(
                recursive=True, file_ext="md", subdir="./content/en/news/security"
            )
        self.version_api = GitHubTagsAPI()
        self.set_api()

    def set_api(self):
        asyncio.run(self.version_api.load_api(["istio/istio"]))

    def updated_advisories(self) -> Set[Advisory]:
        files = self._added_files.union(self._updated_files)
        advisories = []
        for f in files:
            processed_data = self.process_file(f)
            if processed_data:
                advisories.extend(processed_data)
        return self.batch_advisories(advisories)

    def get_pkg_versions_from_ranges(self, version_range_list):
        """Takes a list of version ranges(affected) of a package
        as parameter and returns a tuple of safe package versions and
        vulnerable package versions"""
        all_version = self.version_api.get("istio/istio")
        safe_pkg_versions = []
        vuln_pkg_versions = []
        version_ranges = [RangeSpecifier(r) for r in version_range_list]
        for version in all_version:
            if any([version in v for v in version_ranges]):
                vuln_pkg_versions.append(version)

        safe_pkg_versions = set(all_version) - set(vuln_pkg_versions)
        return safe_pkg_versions, vuln_pkg_versions

    def get_data_from_yaml_lines(self, yaml_lines):
        """Return a mapping of data from a iterable of yaml_lines
        for example :
            ['title: ISTIO-SECURITY-2019-001',
            'description: Incorrect access control.','cves: [CVE-2019-12243]']

            would give {'title':'ISTIO-SECURITY-2019-001',
            'description': 'Incorrect access control.',
            'cves': '[CVE-2019-12243]'}
        """

        return yaml.safe_load("\n".join(yaml_lines))

    def get_yaml_lines(self, lines):
        """The istio advisory file contains lines similar to yaml format .
        This function extracts those lines and return an iterable of lines

        for example :
            lines =
            ---
            title: ISTIO-SECURITY-2019-001
            description: Incorrect access control.
            cves: [CVE-2019-12243]
            ---

        get_yaml_lines(lines) would return
        ['title: ISTIO-SECURITY-2019-001','description: Incorrect access control.'
        ,'cves: [CVE-2019-12243]']
        """

        for index, line in enumerate(lines):
            line = line.strip()
            if line.startswith("---") and index == 0:
                continue
            elif line.endswith("---"):
                break
            else:
                yield line

    def process_file(self, path):

        advisories = []

        data = self.get_data_from_md(path)

        releases = []
        if data.get("releases"):
            for release in data["releases"]:
                # If it is of form "All versions prior to x"
                if "All releases" in release:
                    release = release.strip()
                    release = release.split(" ")
                    releases.append("<" + release[4])
                # If it is of form "a to b"
                elif "to" in release:
                    release = release.strip()
                    release = release.split(" ")
                    lbound = ">=" + release[0]
                    ubound = "<=" + release[2]
                    releases.append(lbound + "," + ubound)
                # If it is a single release
                elif is_release(release):
                    releases.append(release)

        data["release_ranges"] = releases

        if not data.get("cves"):
            data["cves"] = [""]

        for cve_id in data["cves"]:

            if not cve_id.startswith("CVE"):
                cve_id = ""

            safe_pkg_versions = []
            vuln_pkg_versions = []

            if not data.get("release_ranges"):
                data["release_ranges"] = []

            safe_pkg_versions, vuln_pkg_versions = self.get_pkg_versions_from_ranges(
                data["release_ranges"]
            )

            safe_purls_golang = {
                PackageURL(type="golang", name="istio", version=version)
                for version in safe_pkg_versions
            }

            safe_purls_github = {
                PackageURL(type="github", name="istio", version=version)
                for version in safe_pkg_versions
            }
            safe_purls = safe_purls_github.union(safe_purls_golang)

            vuln_purls_golang = {
                PackageURL(type="golang", name="istio", version=version)
                for version in vuln_pkg_versions
            }

            vuln_purls_github = {
                PackageURL(type="github", name="istio", version=version)
                for version in vuln_pkg_versions
            }
            vuln_purls = vuln_purls_github.union(vuln_purls_golang)

            advisories.append(
                Advisory(
                    summary=data["description"],
                    impacted_package_urls=vuln_purls,
                    resolved_package_urls=safe_purls,
                    vulnerability_id=cve_id,
                )
            )

        return advisories

    def get_data_from_md(self, path):
        """Return a mapping of vulnerability data from istio . The data is
        in the form of yaml_lines inside a .md file.
        """

        with open(path) as f:
            yaml_lines = self.get_yaml_lines(f)
            return self.get_data_from_yaml_lines(yaml_lines)
