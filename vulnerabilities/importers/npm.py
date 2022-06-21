#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

# Author: Navonil Das (@NavonilDas)

import asyncio
from typing import List
from typing import Set
from typing import Tuple
from urllib.parse import quote

import pytz
from dateutil.parser import parse
from packageurl import PackageURL
from univers.version_range import VersionRange
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import GitImporter
from vulnerabilities.importer import Reference
from vulnerabilities.package_managers import NpmVersionAPI
from vulnerabilities.utils import load_json
from vulnerabilities.utils import nearest_patched_package

NPM_URL = "https://registry.npmjs.org{}"


class NpmImporter(GitImporter):
    def __enter__(self):
        super(NpmImporter, self).__enter__()
        if not getattr(self, "_added_files", None):
            self._added_files, self._updated_files = self.file_changes(
                recursive=True, file_ext="json", subdir="./vuln/npm"
            )

        self._versions = NpmVersionAPI()
        self.set_api(self.collect_packages())

    def updated_advisories(self) -> Set[AdvisoryData]:
        files = self._updated_files.union(self._added_files)
        advisories = []
        for f in files:
            processed_data = self.process_file(f)
            if processed_data:
                advisories.extend(processed_data)
        return self.batch_advisories(advisories)

    def set_api(self, packages):
        asyncio.run(self._versions.load_api(packages))

    def collect_packages(self):
        packages = set()
        files = self._updated_files.union(self._added_files)
        for f in files:
            data = load_json(f)
            packages.add(data["module_name"].strip())

        return packages

    @property
    def versions(self):  # quick hack to make it patchable
        return self._versions

    def process_file(self, file) -> List[AdvisoryData]:

        record = load_json(file)
        advisories = []
        package_name = record["module_name"].strip()

        publish_date = parse(record["updated_at"])
        publish_date = publish_date.replace(tzinfo=pytz.UTC)

        all_versions = self.versions.get(package_name, until=publish_date).valid_versions
        aff_range = record.get("vulnerable_versions")
        if not aff_range:
            aff_range = ""
        fixed_range = record.get("patched_versions")
        if not fixed_range:
            fixed_range = ""

        if aff_range == "*" or fixed_range == "*":
            return []

        impacted_versions, resolved_versions = categorize_versions(
            all_versions, aff_range, fixed_range
        )

        impacted_purls = _versions_to_purls(package_name, impacted_versions)
        resolved_purls = _versions_to_purls(package_name, resolved_versions)
        vuln_reference = [
            Reference(
                url=NPM_URL.format(f'/-/npm/v1/advisories/{record["id"]}'),
                reference_id=record["id"],
            )
        ]

        for cve_id in record.get("cves") or [""]:
            advisories.append(
                AdvisoryData(
                    summary=record.get("overview", ""),
                    vulnerability_id=cve_id,
                    affected_packages=nearest_patched_package(impacted_purls, resolved_purls),
                    references=vuln_reference,
                )
            )
        return advisories


def _versions_to_purls(package_name, versions):
    purls = {f"pkg:npm/{quote(package_name)}@{v}" for v in versions}
    return [PackageURL.from_string(s) for s in purls]


def normalize_ranges(version_range_string):
    """
    - Splits version range strings with "||" operator into separate ranges.
    - Removes spaces between range operator and range operands
    - Normalizes 'x' ranges
    Example:
    >>> z = normalize_ranges(">=6.1.3 < 7.0.0 || >=7.0.3")
    >>> assert z == [">=6.1.3,<7.0.0", ">=7.0.3"]
    """

    version_ranges = version_range_string.split("||")
    version_ranges = list(map(str.strip, version_ranges))
    for id, version_range in enumerate(version_ranges):

        # TODO: This is cryptic, simplify this if possible
        version_ranges[id] = ",".join(version_range.split())
        version_ranges[id] = version_ranges[id].replace(">=,", ">=")
        version_ranges[id] = version_ranges[id].replace("<=,", "<=")
        version_ranges[id] = version_ranges[id].replace("<=,", "<=")
        version_ranges[id] = version_ranges[id].replace("<,", "<")
        version_ranges[id] = version_ranges[id].replace(">,", ">")

        # "x" is interpretted as wild card character here. These are not part of semver
        # spec. We replace the "x" with aribitarily large number to simulate the effect.
        if ".x." in version_ranges[id]:
            version_ranges[id] = version_ranges[id].replace(".x", ".10000.0")
        if ".x" in version_ranges[id]:
            version_ranges[id] = version_ranges[id].replace(".x", ".10000")

    return version_ranges


def categorize_versions(
    all_versions: Set[str],
    affected_version_range: str,
    fixed_version_range: str,
) -> Tuple[Set[str], Set[str]]:
    """
    Seperate list of affected versions and unaffected versions from all versions
    using the ranges specified.

    :return: impacted, resolved versions
    """
    if not all_versions:
        # NPM registry has no data regarding this package, we skip these
        return set(), set()

    aff_spec = []
    fix_spec = []

    if affected_version_range:
        aff_specs = normalize_ranges(affected_version_range)
        aff_spec = [
            VersionRange.from_scheme_version_spec_string("semver", spec)
            for spec in aff_specs
            if len(spec) >= 3
        ]

    if fixed_version_range:
        fix_specs = normalize_ranges(fixed_version_range)
        fix_spec = [
            VersionRange.from_scheme_version_spec_string("semver", spec)
            for spec in fix_specs
            if len(spec) >= 3
        ]
    aff_ver, fix_ver = set(), set()
    # Unaffected version is that version which is in the fixed_version_range
    # or which is absent in the affected_version_range
    for ver in all_versions:
        ver_obj = SemverVersion(ver)

        if not any([ver_obj in spec for spec in aff_spec]) or any(
            [ver_obj in spec for spec in fix_spec]
        ):
            fix_ver.add(ver)
        else:
            aff_ver.add(ver)

    return aff_ver, fix_ver
