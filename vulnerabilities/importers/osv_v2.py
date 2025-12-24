#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import logging
from typing import Iterable
from typing import List
from typing import Optional

import dateparser
from cvss.exceptions import CVSS3MalformedError
from cvss.exceptions import CVSS4MalformedError
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_constraint import simplify_constraints
from univers.version_range import RANGE_CLASS_BY_SCHEMES
from univers.versions import InvalidVersion
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import PackageCommitPatchData
from vulnerabilities.importer import PatchData
from vulnerabilities.importer import Reference
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipes.advisory import classify_patch_source
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


def parse_advisory_data_v3(
    raw_data: dict, supported_ecosystems, advisory_url: str, advisory_text: str
) -> Optional[AdvisoryData]:
    """
    Return an AdvisoryData build from a ``raw_data`` mapping of OSV advisory and
    a ``supported_ecosystem`` string.
    """
    advisory_id = raw_data.get("id") or ""
    if not advisory_id:
        logger.error(f"Missing advisory id in OSV data: {raw_data}")
        return None
    summary = raw_data.get("summary") or ""
    details = raw_data.get("details") or ""
    summary = build_description(summary=summary, description=details)
    aliases = raw_data.get("aliases") or []

    date_published = get_published_date(raw_data=raw_data)
    severities = list(get_severities(raw_data=raw_data))
    references = get_references_v2(raw_data=raw_data)

    patches = []
    affected_packages = []
    fixed_by_commit_patches = []
    introduced_by_commit_patches = []
    for affected_pkg in raw_data.get("affected") or []:
        purl = get_affected_purl(affected_pkg=affected_pkg, raw_id=advisory_id)

        if not purl or purl.type not in supported_ecosystems:
            logger.error(f"Unsupported package type: {affected_pkg!r} in OSV: {advisory_id!r}")
            continue

        affected_constraints = []
        explicit_affected_constraints = get_explicit_affected_constraints(
            affected_pkg=affected_pkg,
            raw_id=advisory_id,
            supported_ecosystem=purl.type,
        )
        affected_constraints.extend(explicit_affected_constraints)

        last_known_affected = get_last_known_affected__constraint(
            affected_pkg=affected_pkg,
            raw_id=advisory_id,
            supported_ecosystem=purl.type,
        )
        affected_constraints.extend(last_known_affected)

        fixed_constraints = []
        for r in affected_pkg.get("ranges") or []:
            (
                affected_constraint,
                fixed_constraint,
                intro_commits,
                fixed_commits,
            ) = get_version_ranges_constraints(
                ranges=r,
                raw_id=advisory_id,
                supported_ecosystem=purl.type,
            )

            affected_constraints.extend(affected_constraint)
            fixed_constraints.extend(fixed_constraint)

            repo_url = r.get("repo")
            commit_processing_queue = [
                (fixed_commits, fixed_by_commit_patches),
                (intro_commits, introduced_by_commit_patches),
            ]

            for commit_list, target_patch_list in commit_processing_queue:
                for commit_hash in commit_list:
                    try:
                        base_purl, patch_objs = classify_patch_source(
                            url=repo_url, commit_hash=commit_hash, patch_text=None
                        )
                    except Exception as e:
                        logger.error(
                            f"Invalid Commit Data: repo_url:{repo_url!r} - commit_hash: {commit_hash} error: {e} for OSV id: {advisory_id}"
                        )
                        continue
                    for patch_obj in patch_objs:
                        if isinstance(patch_obj, PackageCommitPatchData):
                            target_patch_list.append(patch_obj)
                        elif isinstance(patch_obj, PatchData):
                            patches.append(patch_obj)
                        elif isinstance(patch_obj, ReferenceV2):
                            references.append(patch_obj)

        version_range_class = RANGE_CLASS_BY_SCHEMES.get(purl.type)

        affected_version_range = None
        if affected_constraints:
            try:
                affected_version_range = version_range_class(
                    constraints=simplify_constraints(affected_constraints)
                )
            except Exception as e:
                logger.error(f"Failed to build VersionRange for {advisory_id}: {e}")

        fixed_version_range = None
        if fixed_constraints:
            try:
                fixed_version_range = version_range_class(
                    constraints=simplify_constraints(fixed_constraints)
                )
            except Exception as e:
                logger.error(f"Failed to build VersionRange for {advisory_id}: {e}")

        if (
            fixed_version_range
            or affected_version_range
            or fixed_by_commit_patches
            or introduced_by_commit_patches
        ):
            try:
                affected_packages.append(
                    AffectedPackageV2(
                        package=purl,
                        affected_version_range=affected_version_range,
                        fixed_version_range=fixed_version_range,
                        fixed_by_commit_patches=fixed_by_commit_patches,
                        introduced_by_commit_patches=introduced_by_commit_patches,
                    )
                )
            except Exception as e:
                logger.error(f"Invalid AffectedPackageV2 {e} for {advisory_id}")

    database_specific = raw_data.get("database_specific") or {}
    cwe_ids = database_specific.get("cwe_ids") or []
    weaknesses = list(map(get_cwe_id, cwe_ids))

    if advisory_id in aliases:
        aliases.remove(advisory_id)
    try:
        return AdvisoryData(
            advisory_id=advisory_id,
            aliases=aliases,
            summary=summary,
            references_v2=references,
            severities=severities,
            affected_packages=affected_packages,
            date_published=date_published,
            weaknesses=weaknesses,
            patches=patches,
            url=advisory_url,
            original_advisory_text=advisory_text
            or json.dumps(raw_data, indent=2, ensure_ascii=False),
        )
    except Exception as e:
        logger.error(f"Invalid AdvisoryData for {advisory_id}: {e}")


def extract_events(range_data) -> Iterable[str]:
    """
    Return a list of fixed version strings given a ``fixed_range`` mapping of
    OSV data.

    >>> list(extract_events(
    ... {"type": "SEMVER", "events": [{"introduced": "0"},{"fixed": "1.6.0"}]}))
    [('introduced', '0'), ('fixed', '1.6.0')]

    >>> list(extract_events(
    ... {"type": "ECOSYSTEM","events":[{"introduced": "0"},
    ... {"fixed": "1.0.0"},{"fixed": "9.0.0"}]}))
    [('introduced', '0'), ('fixed', '1.0.0'), ('fixed', '9.0.0')]

    >>> list(extract_events(
    ... {"type": "GIT","events":[{"introduced": "6e5755a2a833bc64852eae12967d0a54d7adf629"},
    ... {"fixed": "c43455749b914feef56b178b256f29b3016146eb"}]}))
    [('introduced', '6e5755a2a833bc64852eae12967d0a54d7adf629'), ('fixed', 'c43455749b914feef56b178b256f29b3016146eb')]
    """
    events = range_data.get("events") or []
    for event_dict in events:
        for event_type, version in event_dict.items():
            yield event_type, version


def get_published_date(raw_data):
    published = raw_data.get("published")
    return published and dateparser.parse(date_string=published)


def get_severities(raw_data) -> Iterable[VulnerabilitySeverity]:
    """
    Yield VulnerabilitySeverity extracted from a mapping of OSV ``raw_data``
    """
    try:
        for severity in raw_data.get("severity") or []:
            vector = severity.get("score")
            valid_vector = vector[:-1] if vector and vector.endswith("/") else vector

            if severity.get("type") == "CVSS_V3":
                system = SCORING_SYSTEMS["cvssv3.1"]
                score = system.compute(valid_vector)
                yield VulnerabilitySeverity(system=system, value=score, scoring_elements=vector)

            elif severity.get("type") == "CVSS_V4":
                system = SCORING_SYSTEMS["cvssv4"]
                score = system.compute(valid_vector)
                yield VulnerabilitySeverity(system=system, value=score, scoring_elements=vector)

            else:
                logger.error(
                    f"Unsupported severity type: {severity!r} for OSV id: {raw_data.get('id')!r}"
                )
    except (CVSS3MalformedError, CVSS4MalformedError) as e:
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


def get_references_v2(raw_data) -> List[Reference]:
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
        references.append(ReferenceV2(url=ref["url"]))
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


def get_explicit_affected_constraints(affected_pkg, raw_id, supported_ecosystem):
    """
    Return a list of explicit version constraints for the ``affected_pkg`` data.
    """
    affected_versions = affected_pkg.get("versions") or []
    constraints = []

    version_range_class = RANGE_CLASS_BY_SCHEMES.get(supported_ecosystem)
    if not version_range_class:
        logger.error(f"unsupported ecosystem {supported_ecosystem}")
        return []

    for version in affected_versions:
        try:
            version_obj = version_range_class.version_class(version)
            constraint = VersionConstraint(comparator="=", version=version_obj)
            constraints.append(constraint)
        except Exception as e:
            logger.error(
                f"Invalid VersionConstraint: {version} " f"for OSV id: {raw_id!r}: error:{e!r}"
            )
    return constraints


def get_last_known_affected__constraint(affected_pkg, raw_id, supported_ecosystem):
    """
    Return the last_known_affected_version_range from the database_specific
    """
    database_specific = affected_pkg.get("database_specific") or {}
    last_known_value = database_specific.get("last_known_affected_version_range")

    if not last_known_value:
        return []

    try:
        version_range_class = RANGE_CLASS_BY_SCHEMES.get(supported_ecosystem)
        version_range = version_range_class.from_native(last_known_value)
        return version_range.constraints

    except Exception as e:
        logger.error(
            f"Invalid VersionConstraint in last_known_affected_version_range: {last_known_value!r} "
            f"for OSV id: {raw_id!r}: error:{e!r}"
        )
        return []


def get_version_ranges_constraints(ranges, raw_id, supported_ecosystem):
    """
    Return a tuple containing lists of affected constraints, fixed constraints,
    introduced commits, and fixed commits
    For example::
    >>> get_version_ranges_constraints(ranges={}, raw_id="GHSA-j3f7-7rmc-6wqj", supported_ecosystem="pypi")
    []
    >>> affected, fixed, intro_commits, fixed_commits = get_version_ranges_constraints(
    ...   ranges={"type": "ECOSYSTEM", "events": [{"fixed": "1.7.0"}]},
    ...   raw_id="GHSA-j3f7-7rmc-6wqj",
    ...   supported_ecosystem="pypi",
    ... )
    >>> affected
    [VersionConstraint(comparator='<', version=PypiVersion(string='1.7.0'))]
    >>> fixed
    [VersionConstraint(comparator='=', version=PypiVersion(string='1.7.0'))]
    >>> intro_commits
    []
    >>> fixed_commits
    []
    """
    fixed_commits = []
    intro_commits = []

    if "type" not in ranges:
        logger.error(f"Invalid Range type for: {ranges} for OSV id: {raw_id!r}")
        return []

    range_type = ranges["type"]

    affected_constraints = []
    fixed_constraints = []
    version_range_class = RANGE_CLASS_BY_SCHEMES.get(supported_ecosystem)

    for event_type, event_value in extract_events(ranges):
        if range_type == "GIT":
            if event_value == "0":
                event_value = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

            if event_type == "fixed":
                fixed_commits.append(event_value)
            elif event_type == "introduced":
                intro_commits.append(event_value)
            else:
                logger.error(f"Invalid Commit: {event_value!r} for OSV id: {raw_id!r}")

        elif range_type in ("ECOSYSTEM", "SEMVER"):
            if range_type == "ECOSYSTEM":
                version_class = version_range_class.version_class if version_range_class else None
            else:
                version_class = SemverVersion  # range_type = "SEMVER"

            try:
                v_obj = version_class(event_value)
            except InvalidVersion:
                logger.error(f"Invalid Version: {event_value!r} for OSV id: {raw_id!r}")
                continue

            if event_type == "introduced":
                if event_value == "0":
                    continue
                constraint = VersionConstraint(comparator=">=", version=v_obj)
                affected_constraints.append(constraint)

            elif event_type == "fixed":
                affected_constraint = VersionConstraint(comparator="<", version=v_obj)
                affected_constraints.append(affected_constraint)

                fixed_constraint = VersionConstraint(comparator="=", version=v_obj)
                fixed_constraints.append(fixed_constraint)

            elif event_type == "last_affected":
                constraint = VersionConstraint(comparator="<=", version=v_obj)
                affected_constraints.append(constraint)
        else:
            logger.error(
                f"Unsupported version constraint type: {event_type}:{event_value!r} for OSV id: {raw_id!r}"
            )

    return (
        affected_constraints,
        fixed_constraints,
        dedupe(intro_commits),
        dedupe(fixed_commits),
    )
