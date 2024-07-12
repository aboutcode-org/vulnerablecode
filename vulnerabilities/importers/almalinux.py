#
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import logging
from pathlib import Path
from typing import Any
from typing import Iterable
from typing import List
from typing import Optional

from packageurl import PackageURL
from univers.version_range import RANGE_CLASS_BY_SCHEMES
from univers.version_range import RpmVersionRange
from univers.versions import InvalidVersion
from univers.versions import RpmVersion
from univers.versions import Version

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importers.osv import extract_fixed_versions
from vulnerabilities.importers.osv import get_published_date
from vulnerabilities.importers.osv import get_references
from vulnerabilities.importers.osv import get_severities

# from vulnerabilities.importers.osv import parse_advisory_data
from vulnerabilities.utils import build_description
from vulnerabilities.utils import dedupe
from vulnerabilities.utils import get_advisory_url
from vulnerabilities.utils import get_cwe_id

logger = logging.getLogger(__name__)
BASE_URL = "https://github.com/AlmaLinux/osv-database"


class AlmaImporter(Importer):
    spdx_license_expression = "MIT License"
    license_url = "https://github.com/AlmaLinux/osv-database/blob/master/LICENSE"
    importer_name = "Alma Linux Importer"

    # for creating purl type is rpm namespace is almalinux names 1:2324:el8

    def advisory_data(self) -> Iterable[AdvisoryData]:
        supported_ecosystems = ["almalinux:8", "almalinux:9"]
        try:
            self.clone(repo_url=self.BASE_URL)
            base_path = Path(self.vcs_response.dest_dir)
            advisory_dirs = base_path / "tree/master/advisories"
            # Iterate throught the directories in the repo and get the .json files
            for file in advisory_dirs.glob("**/*.json"):
                advisory_url = get_advisory_url(
                    file=file,
                    base_path=base_path,
                    url="https://github.com/AlmaLinux/osv-database/blob/master",
                )
                with open(file) as f:
                    raw_data = json.load(f)
                yield parse_advisory_data(raw_data, supported_ecosystems, advisory_url)
        finally:
            if self.vcs_response:
                self.vcs_response.delete()


"""Make follwoing changes:
    alias- done
    summary - done
    affected packages - work
    references - work
    date published - done
    weaknesses - work
    url - done
"""


def parse_advisory_data(raw_data, supported_ecosystems, advisory_url) -> Optional[AdvisoryData]:
    raw_id = raw_data.get("id") or ""
    summary = raw_data.get("summary") or ""
    details = raw_data.get("details") or ""
    summary = build_description(summary=summary, description=details)
    aliases = raw_data.get("aliases") or []
    if raw_id:
        aliases.append(raw_id)
        aliases = dedupe(original=aliases)
    date_published = get_published_date(raw_data=raw_data)
    severities = list(get_severities(raw_data=raw_data))
    references = get_references(raw_data=raw_data, severities=severities)

    affected_packages = []

    for affected_pkg in raw_data.get("affected") or []:
        purl = get_affected_purl(affected_pkg=affected_pkg, raw_id=raw_id)
        ranges = affected_packages.get("ranges") or []
        events = ranges[0].get("events") or []
        if not purl:
            logger.error(f"Unsupported package type: {affected_pkg!r} in OSV: {raw_id!r}")
            continue

        affected_version_range = get_affected_version_range(
            affected_pkg=affected_pkg,
            raw_id=raw_id,
            supported_ecosystem=purl.type,
        )

        for fixed_range in affected_pkg.get("ranges") or []:
            fixed_version = get_fixed_versions(
                fixed_range=fixed_range,
                raw_id=raw_id,
                supported_ecosystem=purl.type,  # can use these information in future to update the get_fixed_version function.
            )

            for version in fixed_version:
                affected_packages.append(
                    AffectedPackage(
                        package=purl,
                        affected_version_range=affected_version_range,
                        fixed_version=version,
                    )
                )

    database_specific = raw_data.get("database_specific") or {}
    cwe_ids = database_specific.get("cwe_ids") or []
    weaknesses = list(map(get_cwe_id, cwe_ids))

    return AdvisoryData(
        aliases=aliases,
        summary=summary,
        references=references,
        affected_packages=affected_packages,
        date_published=date_published,
        weaknesses=weaknesses,
        url=advisory_url,
    )


def get_affected_purl(affected_pkg, raw_id):
    package = affected_pkg.get("package") or {}
    purl = package.get("purl")
    if purl:
        try:
            purl = PackageURL.from_string(purl)
        except ValueError:
            logger.error(
                f"Invalid PackageURL: {purl!r} for OSV "
                f"affected_pkg {affected_pkg} and id: {raw_id}"
            )

    else:
        ecosys = package.get("ecosystem")
        name = package.get("name")
        purl = PackageURL(type="rpm", namespace="almalinux", name=name)

    return PackageURL.from_string(str(purl))


def get_fixed_versions(fixed_range) -> List[Version]:
    fixed_versions = []
    fixed_range_type = fixed_range["type"]
    for version in extract_fixed_versions(fixed_range):
        fixed_versions.append(RpmVersion(version))
    return dedupe(fixed_versions)


def get_affected_version_range(affected_pkg, raw_id, supported_ecosystem):
    """
    Return a univers VersionRange for the ``affected_pkg`` package data mapping
    or None. Use a ``raw_id`` OSV id and ``supported_ecosystem``.
    """
    fixed_range = affected_pkg.get("ranges") or []
    fixed_range = fixed_range[0] if len(fixed_range) > 0 else {}
    fixed_version = get_fixed_versions(fixed_range)[0]
    introduced = fixed_range.get("events") or []
    introduced = introduced[0] if len(introduced) > 0 else {}
    introduced_version = introduced.get("introduced") or ""

    return RpmVersionRange.from_native()
