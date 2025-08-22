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
import traceback

import pytz
from dateutil import parser as dateparser
from univers.version_range import RANGE_CLASS_BY_SCHEMES
from univers.version_range import from_gitlab_native

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.utils import build_description
from vulnerabilities.utils import get_cwe_id


def advisory_dict_to_advisory_data(
    advisory: dict,
    *,
    purl_type_by_gitlab_scheme,
    gitlab_scheme_by_purl_type,
    logger,
    get_purl_fn,
    purl=None,
    advisory_url=None,
):
    """
    Convert a GitLab advisory mapping (already loaded from YAML or JSON) to an
    `AdvisoryData` instance.
    Returns None when no affected or fixed version range can be derived.

    Parameters:
    - advisory: dict per GitLab schema (identifier, package_slug, ...)
    - purl_type_by_gitlab_scheme: mapping of GitLab package type to PackageURL type
    - gitlab_scheme_by_purl_type: inverse mapping of PackageURL type to GitLab type
    - logger: callable like pipeline.log(message, level=logging.LEVEL)
    - get_purl_fn: function to build a version-less PURL from package_slug
    - purl: optional PURL (may include version); used only for context, ranges use
      a version-less PURL derived from package_slug via get_purl_fn
    - advisory_url: optional URL; if not provided, a default URL will be built when possible
    """

    aliases = list(advisory.get("identifiers", []) or [])
    identifier = advisory.get("identifier") or ""
    package_slug = advisory.get("package_slug")

    advisory_id = f"{package_slug}/{identifier}" if package_slug else identifier
    if advisory_id in aliases:
        try:
            aliases.remove(advisory_id)
        except ValueError:
            pass

    summary = build_description(advisory.get("title"), advisory.get("description"))
    urls = advisory.get("urls") or []
    references = [ReferenceV2.from_url(u) for u in urls]

    cwe_ids = advisory.get("cwe_ids") or []
    cwe_list = list(map(get_cwe_id, cwe_ids))

    date_published = dateparser.parse(advisory.get("pubdate")) if advisory.get("pubdate") else None
    if date_published:
        date_published = date_published.replace(tzinfo=pytz.UTC)

    # Prefer a version-less PURL derived from package_slug for affected/fixed ranges
    purl_for_package = None
    if package_slug:
        purl_for_package = get_purl_fn(
            package_slug=package_slug,
            purl_type_by_gitlab_scheme=purl_type_by_gitlab_scheme,
            logger=logger,
        )

    if not purl_for_package:
        logger(
            f"advisory_dict_to_advisory_data: purl is not valid: {package_slug!r}",
            level=logging.ERROR,
        )
        return AdvisoryData(
            advisory_id=advisory_id,
            aliases=aliases,
            summary=summary,
            references_v2=references,
            date_published=date_published,
            url=advisory_url,
            original_advisory_text=json.dumps(advisory, indent=2, ensure_ascii=False),
        )

    # Compute affected and fixed ranges
    affected_version_range = None
    fixed_versions = advisory.get("fixed_versions") or []
    affected_range = advisory.get("affected_range")
    gitlab_native_schemes = {"pypi", "gem", "npm", "go", "packagist", "conan"}
    vrc = RANGE_CLASS_BY_SCHEMES[purl_for_package.type]
    gitlab_scheme = gitlab_scheme_by_purl_type[purl_for_package.type]
    try:
        if affected_range:
            if gitlab_scheme in gitlab_native_schemes:
                affected_version_range = from_gitlab_native(
                    gitlab_scheme=gitlab_scheme, string=affected_range
                )
            else:
                affected_version_range = vrc.from_native(affected_range)
    except Exception as e:
        logger(
            (
                "advisory_dict_to_advisory_data: affected_range is not parsable: "
                f"{affected_range!r} for: {purl_for_package!s} error: {e!r}\n {traceback.format_exc()}"
            ),
            level=logging.ERROR,
        )

    parsed_fixed_versions = []
    for fixed_version in fixed_versions:
        try:
            fixed_version = vrc.version_class(fixed_version)
            parsed_fixed_versions.append(fixed_version.string)
        except Exception as e:
            logger(
                (
                    "advisory_dict_to_advisory_data: fixed_version is not parsable`: "
                    f"{fixed_version!r} error: {e!r}\n {traceback.format_exc()}"
                ),
                level=logging.ERROR,
            )

    if affected_version_range:
        vrc = affected_version_range.__class__

    fixed_version_range = vrc.from_versions(parsed_fixed_versions)
    if not fixed_version_range and not affected_version_range:
        return

    affected_package = AffectedPackageV2(
        package=purl_for_package,
        affected_version_range=affected_version_range,
        fixed_version_range=fixed_version_range,
    )

    # Build a default advisory URL if not provided
    if not advisory_url and package_slug and identifier:
        from urllib.parse import urljoin

        advisory_url = urljoin(
            "https://gitlab.com/gitlab-org/advisories-community/-/blob/main/",
            package_slug + "/" + identifier + ".yml",
        )

    return AdvisoryData(
        advisory_id=advisory_id,
        aliases=aliases,
        summary=summary,
        references_v2=references,
        date_published=date_published,
        affected_packages=[affected_package],
        weaknesses=cwe_list,
        url=advisory_url,
        original_advisory_text=json.dumps(advisory, indent=2, ensure_ascii=False),
    )
