#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import asyncio
from typing import List
from typing import Set

from dateutil.parser import parse
from packageurl import PackageURL
from pytz import UTC
from univers.version_range import VersionRange
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import GitImporter
from vulnerabilities.importer import Reference
from vulnerabilities.package_managers import RubyVersionAPI
from vulnerabilities.utils import load_yaml
from vulnerabilities.utils import nearest_patched_package


class RubyImporter(GitImporter):
    def __enter__(self):
        super(RubyImporter, self).__enter__()

        if not getattr(self, "_added_files", None):
            self._added_files, self._updated_files = self.file_changes(
                recursive=True, file_ext="yml", subdir="./gems"
            )

        self.pkg_manager_api = RubyVersionAPI()
        self.set_api(self.collect_packages())

    def set_api(self, packages):
        asyncio.run(self.pkg_manager_api.load_api(packages))

    def updated_advisories(self) -> Set[AdvisoryData]:
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

    def process_file(self, path) -> List[AdvisoryData]:
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
        all_vers = self.pkg_manager_api.get(package_name, until=publish_time).valid_versions
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

        return AdvisoryData(
            summary=record.get("description", ""),
            affected_packages=nearest_patched_package(impacted_purls, resolved_purls),
            references=references,
            vulnerability_id=cve_id,
        )

    @staticmethod
    def categorize_versions(all_versions, unaffected_version_ranges):
        for id, elem in enumerate(unaffected_version_ranges):
            unaffected_version_ranges[id] = VersionRange.from_scheme_version_spec_string(
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
