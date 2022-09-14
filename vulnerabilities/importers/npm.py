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
from pathlib import Path
from typing import Iterable
from typing import List
from typing import Optional
from urllib.parse import quote

import pytz
from dateutil.parser import parse
from packageurl import PackageURL
from univers.version_range import NpmVersionRange
from univers.versions import InvalidVersion
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import GitImporter
from vulnerabilities.importer import Reference
from vulnerabilities.package_managers import NpmVersionAPI
from vulnerabilities.utils import load_json

NPM_URL = "https://registry.npmjs.org{}"
logger = logging.getLogger(__name__)


class NpmImporter(GitImporter):
    license_url = "https://github.com/nodejs/security-wg/blob/main/LICENSE.md"
    spdx_license_expression = "MIT"

    def __init__(self):
        super().__init__(repo_url="git+https://github.com/nodejs/security-wg.git")

    def advisory_data(self) -> Iterable[AdvisoryData]:
        self.clone()
        path = Path(self.vcs_response.dest_dir)

        glob = "vuln/npm/**/*.json"  # subdir="vuln/npm"
        files = (p for p in path.glob(glob) if p.is_file())
        for file in files:
            print(file)
            record = load_json(file)
            yield parse_advisory_data(record)


def parse_advisory_data(record) -> Optional[AdvisoryData]:
    cves = record.get("cves") or []
    overview = record.get("overview", "")
    package_name = record["module_name"].strip()

    publish_date = parse(record["updated_at"])
    publish_date = publish_date.replace(tzinfo=pytz.UTC)

    pkg_manager_api = NpmVersionAPI()
    all_versions = pkg_manager_api.fetch(package_name)
    aff_range = record.get("vulnerable_versions") or ""
    fixed_range = record.get("patched_versions") or ""

    fixed_versions = get_fixed_version(
        map_all_versions(all_versions), NpmVersionRange.from_native(fixed_range)
    )
    # if aff_range == "*" or fixed_range == "*":
    #    return None

    vuln_reference = [
        Reference(
            url=NPM_URL.format(f'/-/npm/v1/advisories/{record["id"]}'),
            reference_id=record["id"],
        )
    ]

    return AdvisoryData(
        aliases=cves,
        summary=overview,
        affected_packages=[
            AffectedPackage(
                package=PackageURL.from_string(f"pkg:npm/{quote(package_name)}"),
                affected_version_range=NpmVersionRange.from_native(aff_range),
                fixed_version=fixed_version,
            )
            for fixed_version in fixed_versions
        ],
        references=vuln_reference,
        date_published=publish_date,
    )


def map_all_versions(all_versions) -> List[SemverVersion]:
    """
    map all versions from PackageVersion to SemverVersion

    Parameters:
    all_versions (PackageVersion): List of PackageVersion

    Returns:
     List[SemverVersion]: return a list of SemverVersion
    """
    ver_objs = []
    for ver in all_versions:
        try:
            ver_objs.append(SemverVersion(ver.value))
        except InvalidVersion:
            logger.error(f"InvalidVersion {ver.value}")
    return ver_objs


def get_fixed_version(
    all_versions: List[SemverVersion], aff_range: NpmVersionRange
) -> List[SemverVersion]:
    """
    return a list of SemverVersion fixed versions
    """
    try:
        fixed_versions = []
        if not all_versions or not all_versions:
            return fixed_versions
        for v in all_versions:
            if v in aff_range:
                fixed_versions.append(v)
        return fixed_versions
    except Exception as e:
        logger.error(e)
        return []
