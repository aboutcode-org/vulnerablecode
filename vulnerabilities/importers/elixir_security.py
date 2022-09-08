#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import asyncio
from typing import Set

from packageurl import PackageURL
from univers.version_range import VersionRange
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import GitImporter
from vulnerabilities.importer import Reference
from vulnerabilities.package_managers import HexVersionAPI
from vulnerabilities.utils import load_yaml
from vulnerabilities.utils import nearest_patched_package


class ElixirSecurityImporter(GitImporter):
    def __enter__(self):
        super(ElixirSecurityImporter, self).__enter__()

        if not getattr(self, "_added_files", None):
            self._added_files, self._updated_files = self.file_changes(
                recursive=True, file_ext="yml", subdir="./packages"
            )
        self.pkg_manager_api = HexVersionAPI()
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
            if data.get("package"):
                packages.add(data["package"])

        return packages

    def get_versions_for_pkg_from_range_list(self, version_range_list, pkg_name):
        # Takes a list of version ranges(pathced and unaffected) of a package
        # as parameter and returns a tuple of safe package versions and
        # vulnerable package versions

        safe_pkg_versions = []
        vuln_pkg_versions = []
        all_version_list = self.pkg_manager_api.get(pkg_name).valid_versions
        if not version_range_list:
            return [], all_version_list
        version_ranges = [
            VersionRange.from_scheme_version_spec_string("semver", r) for r in version_range_list
        ]
        for version in all_version_list:
            version_obj = SemverVersion(version)
            if any([version_obj in v for v in version_ranges]):
                safe_pkg_versions.append(version)

        vuln_pkg_versions = set(all_version_list) - set(safe_pkg_versions)
        return safe_pkg_versions, vuln_pkg_versions

    def process_file(self, path):
        yaml_file = load_yaml(path)
        pkg_name = yaml_file["package"]
        safe_pkg_versions = []
        vuln_pkg_versions = []
        if not yaml_file.get("patched_versions"):
            yaml_file["patched_versions"] = []

        if not yaml_file.get("unaffected_versions"):
            yaml_file["unaffected_versions"] = []

        safe_pkg_versions, vuln_pkg_versions = self.get_versions_for_pkg_from_range_list(
            yaml_file["patched_versions"] + yaml_file["unaffected_versions"],
            pkg_name,
        )

        if yaml_file.get("cve"):
            cve_id = "CVE-" + yaml_file["cve"]
        else:
            cve_id = ""

        safe_purls = []
        vuln_purls = []

        safe_purls = [
            PackageURL(name=pkg_name, type="hex", version=version) for version in safe_pkg_versions
        ]

        vuln_purls = [
            PackageURL(name=pkg_name, type="hex", version=version) for version in vuln_pkg_versions
        ]

        references = [
            Reference(
                reference_id=yaml_file["id"],
            ),
            Reference(
                url=yaml_file["link"],
            ),
        ]

        return AdvisoryData(
            summary=yaml_file["description"],
            affected_packages=nearest_patched_package(vuln_purls, safe_purls),
            vulnerability_id=cve_id,
            references=references,
        )
