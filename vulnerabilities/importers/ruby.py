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
from typing import Set
from typing import List
from dateutil.parser import parse
from pytz import UTC

from packageurl import PackageURL
from univers.version_specifier import VersionSpecifier
from univers.versions import SemverVersion

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import GitDataSource
from vulnerabilities.data_source import Reference
from vulnerabilities.package_managers import RubyVersionAPI
from vulnerabilities.helpers import load_yaml
from vulnerabilities.helpers import nearest_patched_package


class RubyDataSource(GitDataSource):
    def __enter__(self):
        super(RubyDataSource, self).__enter__()

        if not getattr(self, "_added_files", None):
            self._added_files, self._updated_files = self.file_changes(
                recursive=True, file_ext="yml", subdir="./gems"
            )

        self.pkg_manager_api = RubyVersionAPI()
        self.set_api(self.collect_packages())

    def set_api(self, packages):
        asyncio.run(self.pkg_manager_api.load_api(packages))

    def updated_advisories(self) -> Set[Advisory]:
        files = self._updated_files.union(self._added_files)
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
            if data.get("gem"):
                packages.add(data["gem"])

        return packages

    def process_file(self, path) -> List[Advisory]:
        record = load_yaml(path)
        package_name = record.get("gem")
        if not package_name:
            return

        if "cve" in record:
            cve_id = "CVE-{}".format(record["cve"])
        else:
            return

        publish_time = parse(record["date"]).replace(tzinfo=UTC)
        safe_version_ranges = record.get("patched_versions", [])
        # this case happens when the advisory contain only 'patched_versions' field
        # and it has value None(i.e it is empty :( ).
        if not safe_version_ranges:
            safe_version_ranges = []
        safe_version_ranges += record.get("unaffected_versions", [])
        safe_version_ranges = [i for i in safe_version_ranges if i]

        if not getattr(self, "pkg_manager_api", None):
            self.pkg_manager_api = RubyVersionAPI()
        all_vers = self.pkg_manager_api.get(package_name, until=publish_time)["valid"]
        print(
            f"Ignored {len(self.pkg_manager_api.get(package_name,until=publish_time)['new'])} versions"
        )
        safe_versions, affected_versions = self.categorize_versions(all_vers, safe_version_ranges)

        impacted_purls = [
            PackageURL(
                name=package_name,
                type="gem",
                version=version,
            )
            for version in affected_versions
        ]

        resolved_purls = [
            PackageURL(
                name=package_name,
                type="gem",
                version=version,
            )
            for version in safe_versions
        ]

        references = []
        if record.get("url"):
            references.append(Reference(url=record.get("url")))

        return Advisory(
            summary=record.get("description", ""),
            affected_packages=nearest_patched_package(impacted_purls, resolved_purls),
            references=references,
            vulnerability_id=cve_id,
        )

    @staticmethod
    def categorize_versions(all_versions, unaffected_version_ranges):

        for id, elem in enumerate(unaffected_version_ranges):
            unaffected_version_ranges[id] = VersionSpecifier.from_scheme_version_spec_string(
                "semver", elem
            )

        safe_versions = []
        vulnerable_versions = []
        for i in all_versions:
            vobj = SemverVersion(i)
            is_vulnerable = False
            for ver_rng in unaffected_version_ranges:
                if vobj in ver_rng:
                    safe_versions.append(i)
                    is_vulnerable = True
                    break

            if not is_vulnerable:
                vulnerable_versions.append(i)

        return safe_versions, vulnerable_versions
