#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

# Author: Navonil Das (@NavonilDas)
import logging
from typing import Iterable
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple
from urllib.parse import quote

import pytz
from dateutil.parser import parse
from packageurl import PackageURL
from univers.version_range import NpmVersionRange
from univers.versions import InvalidVersion
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import GitConfig
from vulnerabilities.importer import GitImporter
from vulnerabilities.importer import Reference
from vulnerabilities.package_managers import NpmVersionAPI
from vulnerabilities.package_managers import PackageVersion
from vulnerabilities.utils import load_json
from vulnerabilities.utils import nearest_patched_package

NPM_URL = "https://registry.npmjs.org{}"
logger = logging.getLogger(__name__)


class NpmImporter(GitImporter):
    license_url = "https://github.com/nodejs/security-wg/blob/main/LICENSE.md"
    spdx_license_expression = "MIT"
    config = GitConfig(
        repository_url="https://github.com/nodejs/security-wg.git",
        working_directory="npm",
        branch="main",
    )
    cutoff_timestamp = 1

    def __init__(self):
        super().__init__(config=self.config, cutoff_timestamp=self.cutoff_timestamp)
        self._added_files, self._updated_files = self.file_changes(
            recursive=True, file_ext="json", subdir="vuln/npm"
        )
        self.pkg_manager_api = NpmVersionAPI()

    def parse_advisory_data(self, record) -> Optional[AdvisoryData]:
        package_name = record["module_name"].strip()

        publish_date = parse(record["updated_at"])
        publish_date = publish_date.replace(tzinfo=pytz.UTC)

        all_versions = self.pkg_manager_api.fetch(package_name)
        aff_range = record.get("vulnerable_versions")
        if not aff_range:
            aff_range = ""
        fixed_range = record.get("patched_versions")
        if not fixed_range:
            fixed_range = ""

        # if aff_range == "*" or fixed_range == "*":
        #     return None

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
        cve_id = record.get("cves") or []

        return AdvisoryData(
            aliases=cve_id,
            summary=record.get("overview", ""),
            affected_packages=nearest_patched_package(impacted_purls, resolved_purls),
            references=vuln_reference,
            date_published=publish_date,
        )

    def advisory_data(self) -> Iterable[AdvisoryData]:
        files = self._updated_files.union(self._added_files)
        for file in files:
            record = load_json(file)
            yield self.parse_advisory_data(record)


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
    all_versions: Iterable[PackageVersion],
    affected_version_range: str,
    fixed_version_range: str,
) -> Tuple[Set[SemverVersion], Set[SemverVersion]]:
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
        aff_spec = get_version_range(affected_version_range)

    if fixed_version_range:
        fix_spec = get_version_range(fixed_version_range)

    aff_ver, fix_ver = set(), set()

    # Unaffected version is that version which is in the fixed_version_range
    # or which is absent in the affected_version_range
    for ver in get_all_versions(all_versions):

        if not any([ver in spec for spec in aff_spec]) or any([ver in spec for spec in fix_spec]):
            fix_ver.add(ver)
        else:
            aff_ver.add(ver)

    return aff_ver, fix_ver


def get_version_range(version_range) -> List[NpmVersionRange]:
    fix_specs = normalize_ranges(version_range)
    ver_range_objs = []
    for spec in fix_specs:
        if len(spec) >= 3:
            try:
                ver_range_objs.append(NpmVersionRange.from_string(f"vers:npm/{spec}"))
            except InvalidVersion:
                logger.error(f"InvalidVersionRange {spec}")

    return ver_range_objs


def get_all_versions(all_versions) -> List[SemverVersion]:
    """

    Args:
        all_versions:

    Returns:

    """
    ver_objs = []
    for ver in all_versions:
        try:
            ver_objs.append(SemverVersion(ver.value))
        except InvalidVersion:
            logger.error(f"InvalidVersion {ver.value}")
    return ver_objs
