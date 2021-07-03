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
import pytz
import re
from dateutil import parser
from typing import Set

import saneyaml
from packageurl import PackageURL
from univers.version_specifier import VersionSpecifier
from univers.versions import SemverVersion

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import GitDataSource
from vulnerabilities.data_source import Reference
from vulnerabilities.helpers import nearest_patched_package
from vulnerabilities.helpers import split_markdown_front_matter
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

    def get_pkg_versions_from_ranges(self, version_range_list, release_date):
        """Takes a list of version ranges(affected) of a package
        as parameter and returns a tuple of safe package versions and
        vulnerable package versions"""
        all_version = self.version_api.get("istio/istio", release_date).valid_versions
        safe_pkg_versions = []
        vuln_pkg_versions = []
        version_ranges = [
            VersionSpecifier.from_scheme_version_spec_string("semver", r)
            for r in version_range_list
        ]
        for version in all_version:
            version_obj = SemverVersion(version)
            if any([version_obj in v for v in version_ranges]):
                vuln_pkg_versions.append(version)

        safe_pkg_versions = set(all_version) - set(vuln_pkg_versions)
        return safe_pkg_versions, vuln_pkg_versions

    def process_file(self, path):

        advisories = []

        data = self.get_data_from_md(path)
        release_date = parser.parse(data["publishdate"]).replace(tzinfo=pytz.UTC)

        releases = []
        if data.get("releases"):
            for release in data["releases"]:
                # If it is of form "All releases prior to x"
                if "All releases prior" in release:
                    release = release.strip()
                    release = release.split(" ")
                    releases.append("<" + release[4])

                # Eg. 'All releases 1.5 and later'
                elif "All releases" in release and "and later" in release:
                    release = release.split()[2].strip()
                    releases.append(f">={release}")

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
                data["release_ranges"], release_date
            )

            affected_packages = []

            safe_purls_golang = [
                PackageURL(type="golang", name="istio", version=version)
                for version in safe_pkg_versions
            ]

            vuln_purls_golang = [
                PackageURL(type="golang", name="istio", version=version)
                for version in vuln_pkg_versions
            ]

            affected_packages.extend(nearest_patched_package(vuln_purls_golang, safe_purls_golang))

            safe_purls_github = [
                PackageURL(type="github", name="istio", version=version)
                for version in safe_pkg_versions
            ]

            vuln_purls_github = [
                PackageURL(type="github", name="istio", version=version)
                for version in vuln_pkg_versions
            ]

            affected_packages.extend(nearest_patched_package(vuln_purls_github, safe_purls_github))

            advisories.append(
                Advisory(
                    vulnerability_id=cve_id,
                    summary=data["description"],
                    affected_packages=affected_packages,
                    references=[
                        Reference(
                            reference_id=data["title"],
                            url=f"https://istio.io/latest/news/security/{data['title']}/",
                        )
                    ],
                )
            )

        return advisories

    def get_data_from_md(self, path):
        """Return a mapping of vulnerability data extracted from an advisory."""

        with open(path) as f:
            front_matter, _ = split_markdown_front_matter(f.read())
            return saneyaml.load(front_matter)
