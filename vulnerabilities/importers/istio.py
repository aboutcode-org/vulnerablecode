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

from dephell_specifier import RangeSpecifier
from packageurl import PackageURL

from vulnerabilities.data_source import Advisory, GitDataSource, Reference
from vulnerabilities.package_managers import GitHubTagsAPI


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
        files = self._updated_files
        advisories = []
        for f in files:
            processed_data = self.process_file(f)
            if processed_data:
                advisories.extend(processed_data)
        return self.batch_advisories(advisories)

    def added_advisories(self) -> Set[Advisory]:
        files = self._added_files
        advisories = []
        for f in files:
            processed_data = self.process_file(f)
            if processed_data:
                advisories.extend(processed_data)
        return self.batch_advisories(advisories)

    def get_versions_for_pkg_from_range_list(self, version_range_list):
        # Takes a list of version ranges(affected) of a package
        # as parameter and returns a tuple of safe package versions and
        # vulnerable package versions

        safe_pkg_versions = []
        vuln_pkg_versions = []
        all_version_list = self.version_api.get("istio/istio")
        if not version_range_list:
            return all_version_list, []
        version_ranges = {RangeSpecifier(r) for r in version_range_list}
        for version in all_version_list:
            if any([version in v for v in version_ranges]):
                vuln_pkg_versions.append(version)

        safe_pkg_versions = set(all_version_list) - set(vuln_pkg_versions)
        return safe_pkg_versions, vuln_pkg_versions

    def get_data_from_md(self, file):
        data = {}
        for line in file:
            line = line.strip()
            line = line.split()
            if len(line) > 0 and line is not None:

                start = line[0]

                if start == "title:":
                    data["title"] = " ".join(line[1:])
                elif start == "description:":
                    data["description"] = " ".join(line[1:])
                elif start == "cves:":
                    data["cves"] = " ".join(line[1:])
                    data["cves"] = data["cves"].replace("[", "")
                    data["cves"] = data["cves"].replace("]", "")
                    data["cves"] = data["cves"].split(",")

                elif start == "releases:":
                    data["releases"] = " ".join(line[1:])
                    data["releases"] = data["releases"].replace("[", "")
                    data["releases"] = data["releases"].replace("]", "")
                    data["releases"] = data["releases"].replace('"', "")
                    data["releases"] = data["releases"].split(",")
        releases = []
        if data.get("releases"):
            for release in data["releases"]:
                release = release.strip()
                release = release.split(" ")
                if len(release) > 2:
                    lbound = ">=" + release[0]
                    ubound = "<=" + release[2]
                    releases.append(lbound + "," + ubound)
        data["releases"] = releases

        return data

    def process_file(self, path):

        advisories = []

        with open(path) as f:
            data = {}

            data = self.get_data_from_md(f)

            if not data.get("cves"):
                data["cves"] = [""]

            for cve_id in data["cves"]:

                if not cve_id.startswith("CVE"):
                    continue

                safe_pkg_versions = []
                vuln_pkg_versions = []

                if not data.get("releases"):
                    data["releases"] = []

                (
                    safe_pkg_versions,
                    vuln_pkg_versions,
                ) = self.get_versions_for_pkg_from_range_list(data["releases"])

                safe_purls = []
                vuln_purls = []

                cve_id = cve_id

                safe_purls = {
                    PackageURL(name="istio", type="golang", version=version)
                    for version in safe_pkg_versions
                }

                vuln_purls = {
                    PackageURL(name="istio", type="golang", version=version)
                    for version in vuln_pkg_versions
                }

                advisories.append(
                    Advisory(
                        summary=data["description"],
                        impacted_package_urls=vuln_purls,
                        resolved_package_urls=safe_purls,
                        cve_id=cve_id,
                    )
                )

        return advisories
