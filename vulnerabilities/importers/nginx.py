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
import dataclasses

import requests
from packageurl import PackageURL
from bs4 import BeautifulSoup
from univers.version_specifier import VersionSpecifier
from univers.versions import SemverVersion

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import DataSourceConfiguration
from vulnerabilities.data_source import Reference
from vulnerabilities.package_managers import GitHubTagsAPI
from vulnerabilities.helpers import nearest_patched_package


@dataclasses.dataclass
class NginxDataSourceConfiguration(DataSourceConfiguration):
    etags: dict


class NginxDataSource(DataSource):
    CONFIG_CLASS = NginxDataSourceConfiguration

    url = "http://nginx.org/en/security_advisories.html"

    def set_api(self):
        self.version_api = GitHubTagsAPI()
        asyncio.run(self.version_api.load_api(["nginx/nginx"]))

        # For some reason nginx tags it's releases are in the form of `release-1.2.3`
        # Chop off the `release-` part here.
        for index, version in enumerate(self.version_api.cache["nginx/nginx"]):
            self.version_api.cache["nginx/nginx"][index] = version.replace("release-", "")

    def updated_advisories(self):
        advisories = []
        self.set_api()
        data = requests.get(self.url).content
        advisories.extend(self.to_advisories(data))
        return self.batch_advisories(advisories)

    def to_advisories(self, data):
        advisories = []
        soup = BeautifulSoup(data, features="lxml")
        vuln_list = soup.select("li p")

        # Example value of `vuln_list` :
        # ['Excessive CPU usage in HTTP/2 with small window updates',
        #  <br/>,
        #  'Severity: medium',
        #  <br/>,
        #  <a href="http://mailman.nginx.org/pipermail/nginx-announce/2019/000249.html">Advisory</a>,  # nopep8
        #  <br/>,
        #  <a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9511">CVE-2019-9511</a>,
        #  <br/>,
        #  'Not vulnerable: 1.17.3+, 1.16.1+',
        #  <br/>,
        #  'Vulnerable: 1.9.5-1.17.2']

        for vuln_info in vuln_list:
            references = []
            for index, child in enumerate(vuln_info.children):
                if index == 0:
                    # type of this child is bs4.element.NavigableString.
                    # Hence cast it into standard string
                    summary = str(child)
                    continue

                #  hasattr(child, "attrs") == False for bs4.element.NavigableString
                if hasattr(child, "attrs") and child.attrs.get("href"):
                    link = child.attrs["href"]
                    references.append(Reference(url=link))
                    if "cve.mitre.org" in link:
                        cve_id = child.text
                    continue

                if "Not vulnerable" in child:
                    fixed_packages = self.extract_fixed_pkgs(child)
                    continue

                if "Vulnerable" in child:
                    vulnerable_packages = self.extract_vuln_pkgs(child)
                    continue

            advisories.append(
                Advisory(
                    vulnerability_id=cve_id,
                    summary=summary,
                    affected_packages=nearest_patched_package(vulnerable_packages, fixed_packages),
                )
            )

        return advisories

    def extract_fixed_pkgs(self, vuln_info):
        vuln_status, version_info = vuln_info.split(": ")
        if "none" in version_info:
            return {}

        raw_ranges = version_info.split(",")
        version_ranges = []
        for rng in raw_ranges:
            # Eg. "1.7.3+" gets converted to VersionSpecifier.from_scheme_version_spec_string("semver","^1.7.3")
            # The advisory in this case uses `+` in the sense that any version
            # with greater or equal `minor` version satisfies the range.
            # "1.7.4" satisifes "1.7.3+", but "1.8.4" does not. "1.7.3+" has same
            # semantics as that of "^1.7.3"

            version_ranges.append(
                VersionSpecifier.from_scheme_version_spec_string("semver", "^" + rng[:-1])
            )

        valid_versions = find_valid_versions(self.version_api.get("nginx/nginx"), version_ranges)

        return [
            PackageURL(type="generic", name="nginx", version=version) for version in valid_versions
        ]

    def extract_vuln_pkgs(self, vuln_info):
        vuln_status, version_infos = vuln_info.split(": ")
        if "none" in version_infos:
            return {}

        version_ranges = []
        windows_only = False
        for version_info in version_infos.split(", "):
            if version_info == "all":
                # This is misleading since eventually some version get fixed.
                continue

            if "-" not in version_info:
                # These are discrete versions
                version_ranges.append(
                    VersionSpecifier.from_scheme_version_spec_string("semver", version_info[0])
                )
                continue

            windows_only = "nginx/Windows" in version_info
            version_info = version_info.replace("nginx/Windows", "")
            lower_bound, upper_bound = version_info.split("-")

            version_ranges.append(
                VersionSpecifier.from_scheme_version_spec_string(
                    "semver", f">={lower_bound},<={upper_bound}"
                )
            )

        valid_versions = find_valid_versions(self.version_api.get("nginx/nginx"), version_ranges)
        qualifiers = {}
        if windows_only:
            qualifiers["os"] = "windows"

        return [
            PackageURL(type="generic", name="nginx", version=version, qualifiers=qualifiers)
            for version in valid_versions
        ]


def find_valid_versions(versions, version_ranges):
    valid_versions = set()
    for version in versions:
        version_obj = SemverVersion(version)
        if any([version_obj in ver_range for ver_range in version_ranges]):
            valid_versions.add(version)

    return valid_versions
