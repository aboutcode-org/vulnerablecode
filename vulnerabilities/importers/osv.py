#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from typing import Iterable
from typing import List
from typing import Optional

import dateparser
from cvss.exceptions import CVSS3MalformedError
from packageurl import PackageURL
from univers.version_range import RANGE_CLASS_BY_SCHEMES
from univers.versions import InvalidVersion
from univers.versions import SemverVersion
from univers.versions import Version

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerabilities.utils import build_description
from vulnerabilities.utils import dedupe
from vulnerabilities.utils import get_cwe_id

logger = logging.getLogger(__name__)

PURL_TYPE_BY_OSV_ECOSYSTEM = {
    "npm": "npm",
    "pypi": "pypi",
    "maven": "maven",
    "nuget": "nuget",
    "packagist": "composer",
    "rubygems": "gem",
    "go": "golang",
    "hex": "hex",
    "cargo": "cargo",
}


def parse_advisory_data(
    raw_data: dict, supported_ecosystems, advisory_url: str
) -> Optional[AdvisoryData]:
    """
    Return an AdvisoryData build from a ``raw_data`` mapping of OSV advisory and
    a ``supported_ecosystem`` string.
    """
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

        if not purl or purl.type not in supported_ecosystems:
            logger.error(f"Unsupported package type: {affected_pkg!r} in OSV: {raw_id!r}")
            continue

        affected_version_range = get_affected_version_range(
            affected_pkg=affected_pkg,
            raw_id=raw_id,
            supported_ecosystem=purl.type,
        )

        for fixed_range in affected_pkg.get("ranges") or []:
            fixed_version = get_fixed_versions(
                fixed_range=fixed_range, raw_id=raw_id, supported_ecosystem=purl.type
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


def extract_fixed_versions(fixed_range) -> Iterable[str]:
    """
    Return a list of fixed version strings given a ``fixed_range`` mapping of
    OSV data.

    >>> list(extract_fixed_versions(
    ... {"type": "SEMVER", "events": [{"introduced": "0"},{"fixed": "1.6.0"}]}))
    ['1.6.0']

    >>> list(extract_fixed_versions(
    ... {"type": "ECOSYSTEM","events":[{"introduced": "0"},
    ... {"fixed": "1.0.0"},{"fixed": "9.0.0"}]}))
    ['1.0.0', '9.0.0']
    """
    for event in fixed_range.get("events") or []:
        fixed = event.get("fixed")
        if fixed:
            yield fixed


def get_published_date(raw_data):
    published = raw_data.get("published")
    return published and dateparser.parse(date_string=published)


def get_severities(raw_data) -> Iterable[VulnerabilitySeverity]:
    """
    Yield VulnerabilitySeverity extracted from a mapping of OSV ``raw_data``
    """
    try:
        for severity in raw_data.get("severity") or []:
            if severity.get("type") == "CVSS_V3":
                vector = severity.get("score")
                # remove the / from the end of the vector if / exist
                valid_vector = vector[:-1] if vector and vector[-1] == "/" else vector
                system = SCORING_SYSTEMS["cvssv3.1"]
                score = system.compute(valid_vector)
                yield VulnerabilitySeverity(system=system, value=score, scoring_elements=vector)

            else:
                logger.error(
                    f"Unsupported severity type: {severity!r} for OSV id: {raw_data['id']!r}"
                )
    except CVSS3MalformedError as e:
        logger.error(f"Invalid severity {e}")

    ecosystem_specific = raw_data.get("ecosystem_specific") or {}
    severity = ecosystem_specific.get("severity")
    if severity:
        yield VulnerabilitySeverity(
            system=SCORING_SYSTEMS["generic_textual"],
            value=severity,
        )

    database_specific = raw_data.get("database_specific") or {}
    severity = database_specific.get("severity")
    if severity:
        yield VulnerabilitySeverity(
            system=SCORING_SYSTEMS["generic_textual"],
            value=severity,
        )


def get_references(raw_data, severities) -> List[Reference]:
    """
    Return a list Reference extracted from a mapping of OSV ``raw_data`` given a
    ``severities`` list of VulnerabilitySeverity.
    """
    references = []
    for ref in raw_data.get("references") or []:
        if not ref:
            continue
        url = ref["url"]
        if not url:
            logger.error(f"Reference without URL : {ref!r} for OSV id: {raw_data['id']!r}")
            continue
        references.append(Reference(url=ref["url"], severities=severities))
    return references


def get_affected_purl(affected_pkg, raw_id):
    """
    Return an affected PackageURL or None given a mapping of ``affected_pkg``
    data and a ``raw_id``.
    """
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
        if ecosys and name:
            ecosys = ecosys.lower()
            purl_type = PURL_TYPE_BY_OSV_ECOSYSTEM.get(ecosys)
            if not purl_type:
                return
            namespace = ""
            if purl_type == "maven":
                namespace, _, name = name.partition(":")

            purl = PackageURL(type=purl_type, namespace=namespace, name=name)
        else:
            logger.error(
                f"No PackageURL possible: {purl!r} for affected_pkg {affected_pkg} for OSV id: {raw_id}"
            )
            return
    try:
        package_url = PackageURL.from_string(str(purl))
        return package_url
    except:
        logger.error(
            f"Invalid PackageURL: {purl!r} for affected_pkg {affected_pkg} for OSV id: {raw_id}"
        )
        return None


def get_affected_version_range(affected_pkg, raw_id, supported_ecosystem):
    """
    Return a univers VersionRange for the ``affected_pkg`` package data mapping
    or None. Use a ``raw_id`` OSV id and ``supported_ecosystem``.
    """
    affected_versions = affected_pkg.get("versions")
    if affected_versions:
        try:
            return RANGE_CLASS_BY_SCHEMES[supported_ecosystem].from_versions(affected_versions)
        except Exception as e:
            logger.error(
                f"Invalid VersionRange  for affected_pkg: {affected_pkg} "
                f"for OSV id: {raw_id!r}: error:{e!r}"
            )


def get_fixed_versions(fixed_range, raw_id, supported_ecosystem) -> List[Version]:
    """
    Return a list of unique fixed univers Versions given a ``fixed_range``
    univers VersionRange and a ``raw_id``.
    For example::
    >>> get_fixed_versions(fixed_range={}, raw_id="GHSA-j3f7-7rmc-6wqj", supported_ecosystem="pypi",)
    []
    >>> get_fixed_versions(
    ...   fixed_range={"type": "ECOSYSTEM", "events": [{"fixed": "1.7.0"}], },
    ...   raw_id="GHSA-j3f7-7rmc-6wqj",
    ...   supported_ecosystem="pypi",
    ... )
    [PypiVersion(string='1.7.0')]
    """
    fixed_versions = []
    if "type" not in fixed_range:
        logger.error(f"Invalid fixed_range type for: {fixed_range} for OSV id: {raw_id!r}")
        return []

    fixed_range_type = fixed_range["type"]

    version_range_class = RANGE_CLASS_BY_SCHEMES.get(supported_ecosystem)
    version_class = version_range_class.version_class if version_range_class else None

    for version in extract_fixed_versions(fixed_range):
        if fixed_range_type == "ECOSYSTEM":
            try:
                if not version_class:
                    raise InvalidVersion(
                        f"Unsupported version for ecosystem: {supported_ecosystem}"
                    )
                fixed_versions.append(version_class(version))
            except InvalidVersion:
                logger.error(
                    f"Invalid version class: {version_class} - {version!r} for OSV id: {raw_id!r}"
                )

        elif fixed_range_type == "SEMVER":
            try:
                fixed_versions.append(SemverVersion(version))
            except InvalidVersion:
                logger.error(f"Invalid SemverVersion: {version!r} for OSV id: {raw_id!r}")
        else:
            logger.error(f"Unsupported fixed version type: {version!r} for OSV id: {raw_id!r}")

        # if fixed_range_type == "GIT":
        # TODO add GitHubVersion univers fix_version
        #     logger.error(f"NotImplementedError GIT Version - {raw_id !r} - {i !r}")

    return dedupe(fixed_versions)
