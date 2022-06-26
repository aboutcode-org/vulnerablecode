#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from typing import Iterable
from typing import List
from typing import Optional

import dateparser
from packageurl import PackageURL
from univers.version_range import RANGE_CLASS_BY_SCHEMES
from univers.versions import InvalidVersion
from univers.versions import PypiVersion
from univers.versions import SemverVersion
from univers.versions import Version

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerabilities.utils import build_description
from vulnerabilities.utils import dedupe

logger = logging.getLogger(__name__)


def parse_advisory_data(raw_data: dict, supported_ecosystem) -> Optional[AdvisoryData]:
    raw_id = raw_data.get("id") or ""
    summary = raw_data.get("summary") or ""
    details = raw_data.get("details") or ""
    summary = build_description(summary=summary, description=details)
    aliases = raw_data.get("aliases") or []
    if raw_id:
        aliases.append(raw_id)
    date_published = get_published_date(raw_data)
    severity = list(get_severities(raw_data))
    references = get_references(raw_data, severity)

    affected_packages = []
    if "affected" not in raw_data:
        logger.error(f"affected_packages not found - {raw_id !r}")
        return AdvisoryData(
            aliases=aliases,
            summary=summary,
            references=references,
            affected_packages=[],
            date_published=date_published,
        )

    for affected_pkg in raw_data.get("affected") or []:
        purl = get_affected_purl(affected_pkg, raw_id)
        if purl.type != supported_ecosystem:
            logger.error(
                f"un supported ecosystem package found in the advisories: {purl} - from: {raw_id !r}"
            )
            continue

        affected_version_range = get_affected_version_range(
            affected_pkg, raw_id, supported_ecosystem
        )
        for fixed_range in affected_pkg.get("ranges", []):
            fixed_version = get_fixed_version(fixed_range, raw_id)

            for version in fixed_version:
                affected_packages.append(
                    AffectedPackage(
                        package=purl,
                        affected_version_range=affected_version_range,
                        fixed_version=version,
                    )
                )

    return AdvisoryData(
        aliases=aliases,
        summary=summary,
        affected_packages=affected_packages,
        references=references,
        date_published=date_published,
    )


def fixed_filter(fixed_range) -> Iterable[str]:
    """
    Return a list of fixed version strings given a ``fixed_range`` mapping of OSV data.
    >>> list(fixed_filter({"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.6.0"}]}))
    ['1.6.0']
    >>> list(fixed_filter({"type": "ECOSYSTEM","events":[{"introduced": "0"},{"fixed": "1.0.0"},{"fixed": "9.0.0"}]}))
    ['1.0.0', '9.0.0']
    """
    for event in fixed_range.get("events") or []:
        fixed = event.get("fixed")
        if fixed:
            yield fixed


def get_published_date(raw_data):
    published = raw_data.get("published")
    return published and dateparser.parse(published)


def get_severities(raw_data) -> Iterable[VulnerabilitySeverity]:
    for sever_list in raw_data.get("severity") or []:
        if sever_list.get("type") == "CVSS_V3":
            yield VulnerabilitySeverity(
                system=SCORING_SYSTEMS["cvssv3.1_vector"], value=sever_list["score"]
            )
        else:
            logger.error(f"NotImplementedError severity type- {raw_data['id']!r}")

    ecosys = raw_data.get("ecosystem_specific") or {}
    sever = ecosys.get("severity")
    if sever:
        yield VulnerabilitySeverity(
            system=SCORING_SYSTEMS["generic_textual"],
            value=sever,
        )

    database_specific = raw_data.get("database_specific") or {}
    sever = database_specific.get("severity")
    if sever:
        yield VulnerabilitySeverity(
            system=SCORING_SYSTEMS["generic_textual"],
            value=sever,
        )


def get_references(raw_data, severities) -> List[Reference]:
    references = raw_data.get("references") or []
    return [Reference(url=ref["url"], severities=severities) for ref in references if ref]


def get_affected_purl(affected_pkg, raw_id):
    package = affected_pkg.get("package") or {}
    purl = package.get("purl")
    if purl:
        try:
            return PackageURL.from_string(purl)
        except ValueError:
            logger.error(f"PackageURL ValueError - {raw_id !r} - purl: {purl !r}")

    ecosys = package.get("ecosystem")
    name = package.get("name")
    if ecosys and name:
        return PackageURL(type=ecosys, name=name)
    else:
        logger.error(f"purl affected_pkg not found - {raw_id !r}")


def get_affected_version_range(affected_pkg, raw_id, supported_ecosystem):
    affected_versions = affected_pkg.get("versions")
    if affected_versions:
        try:
            return RANGE_CLASS_BY_SCHEMES[supported_ecosystem].from_versions(affected_versions)
        except Exception as e:
            logger.error(
                f"InvalidVersionRange affected_pkg_version_range Error - {raw_id !r} {e!r}"
            )
    # else:
    #     logger.error(f"affected_pkg_version_range not found - {raw_id !r} ")


def get_fixed_version(fixed_range, raw_id) -> List[Version]:
    """
    Return a list of fixed versions, using fixed_filter we get the list of fixed version strings,
    then we pass every element to their univers.versions , then we dedupe the result
    >>> get_fixed_version({}, "GHSA-j3f7-7rmc-6wqj")
    []
    >>> get_fixed_version({"type": "ECOSYSTEM", "events": [{"fixed": "1.7.0"}]}, "GHSA-j3f7-7rmc-6wqj")
    [PypiVersion(string='1.7.0')]
    """
    fixed_version = []
    if "type" not in fixed_range:
        logger.error(f"Invalid type - {raw_id!r}")
    else:
        list_fixed = fixed_filter(fixed_range)
        fixed_range_type = fixed_range["type"]
        for i in list_fixed:
            if fixed_range_type == "ECOSYSTEM":
                try:
                    fixed_version.append(PypiVersion(i))
                except InvalidVersion:
                    logger.error(f"Invalid Version - PypiVersion - {raw_id !r} - {i !r}")
            if fixed_range_type == "SEMVER":
                try:
                    fixed_version.append(SemverVersion(i))
                except InvalidVersion:
                    logger.error(f"Invalid Version - SemverVersion - {raw_id !r} - {i !r}")
            if fixed_range_type == "GIT":
                # TODO add GitHubVersion univers fix_version
                logger.error(f"NotImplementedError GIT Version - {raw_id !r} - {i !r}")

    return dedupe(fixed_version)
