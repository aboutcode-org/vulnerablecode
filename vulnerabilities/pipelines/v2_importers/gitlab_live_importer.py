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
from typing import Iterable
from urllib.parse import urljoin

import pytz
from dateutil import parser as dateparser
from packageurl import PackageURL
from univers.version_range import RANGE_CLASS_BY_SCHEMES
from univers.version_range import VersionRange
from univers.version_range import from_gitlab_native

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.pipelines.v2_importers.gitlab_importer import get_purl
from vulnerabilities.utils import build_description
from vulnerabilities.utils import get_cwe_id
from vulntotal.datasources.gitlab import get_casesensitive_slug
from vulntotal.datasources.gitlab_api import fetch_gitlab_advisories_for_purl
from vulntotal.datasources.gitlab_api import get_estimated_advisories_count


class GitLabLiveImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    GitLab Live Importer Pipeline

    Collect advisory from GitLab Advisory Database (Open Source Edition) for a single PURL.
    """

    pipeline_id = "gitlab_live_importer_v2"
    spdx_license_expression = "MIT"
    license_url = "https://gitlab.com/gitlab-org/advisories-community/-/blob/main/LICENSE"
    supported_types = ["pypi", "npm", "maven", "nuget", "composer", "conan", "gem"]

    @classmethod
    def steps(cls):
        return (
            cls.get_purl_inputs,
            cls.collect_and_store_advisories,
        )

    def get_purl_inputs(self):
        purl = self.inputs["purl"]
        if not purl:
            raise ValueError("PURL is required for GitLabLiveImporterPipeline")

        if isinstance(purl, str):
            purl = PackageURL.from_string(purl)

        if not isinstance(purl, PackageURL):
            raise ValueError(f"Object of type {type(purl)} {purl!r} is not a PackageURL instance")

        if purl.type not in self.supported_types:
            raise ValueError(
                f"PURL: {purl!s} is not among the supported package types {self.supported_types!r}"
            )

        if not purl.version:
            raise ValueError(f"PURL: {purl!s} is expected to have a version")

        self.purl = purl

    purl_type_by_gitlab_scheme = {
        "conan": "conan",
        "gem": "gem",
        # Entering issue to parse go package names https://github.com/nexB/vulnerablecode/issues/742
        # "go": "golang",
        "maven": "maven",
        "npm": "npm",
        "nuget": "nuget",
        "packagist": "composer",
        "pypi": "pypi",
    }

    gitlab_scheme_by_purl_type = {v: k for k, v in purl_type_by_gitlab_scheme.items()}

    def advisories_count(self):
        return get_estimated_advisories_count(
            self.purl, self.gitlab_scheme_by_purl_type, get_casesensitive_slug
        )

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        advisories = fetch_gitlab_advisories_for_purl(
            self.purl, self.gitlab_scheme_by_purl_type, get_casesensitive_slug
        )

        input_version = self.purl.version
        vrc = RANGE_CLASS_BY_SCHEMES[self.purl.type]
        version_obj = vrc.version_class(input_version) if input_version else None

        for advisory in advisories:
            advisory_data = self._advisory_dict_to_advisory_data(advisory)

            affected = False
            for affected_package in advisory_data.affected_packages:
                vrange = affected_package.affected_version_range
                if vrange and version_obj in vrange:
                    affected = True
                    break
            if affected:
                yield advisory_data

    def _advisory_dict_to_advisory_data(self, advisory):
        return advisory_dict_to_advisory_data(
            advisory=advisory,
            purl_type_by_gitlab_scheme=self.purl_type_by_gitlab_scheme,
            gitlab_scheme_by_purl_type=self.gitlab_scheme_by_purl_type,
            logger=self.log,
            purl=self.purl,
        )


def advisory_dict_to_advisory_data(
    advisory: dict,
    purl_type_by_gitlab_scheme,
    gitlab_scheme_by_purl_type,
    logger,
    purl=None,
    advisory_url=None,
):
    """
    Convert a GitLab advisory dict to AdvisoryDataV2.
    """
    aliases = advisory.get("identifiers", [])
    identifier = advisory.get("identifier", "")
    package_slug = advisory.get("package_slug")

    advisory_id = f"{package_slug}/{identifier}" if package_slug else identifier
    if advisory_id in aliases:
        aliases.remove(advisory_id)

    summary = build_description(advisory.get("title"), advisory.get("description"))
    urls = advisory.get("urls", [])
    references = [ReferenceV2.from_url(u) for u in urls]

    cwe_ids = advisory.get("cwe_ids") or []
    cwe_list = list(map(get_cwe_id, cwe_ids))

    date_published = dateparser.parse(advisory.get("pubdate"))
    date_published = date_published.replace(tzinfo=pytz.UTC)

    # Determine purl if not provided
    if not purl:
        purl = get_purl(
            package_slug=package_slug,
            purl_type_by_gitlab_scheme=purl_type_by_gitlab_scheme,
            logger=logger,
        )

    if not purl:
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
        )

    affected_version_range = None
    fixed_versions = advisory.get("fixed_versions") or []
    affected_range = advisory.get("affected_range")
    gitlab_native_schemes = set(["pypi", "gem", "npm", "go", "packagist", "conan"])
    vrc: VersionRange = RANGE_CLASS_BY_SCHEMES[purl.type]
    gitlab_scheme = gitlab_scheme_by_purl_type[purl.type]
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
            f"advisory_dict_to_advisory_data: affected_range is not parsable: {affected_range!r} for: {purl!s} error: {e!r}\n {traceback.format_exc()}",
            level=logging.ERROR,
        )

    parsed_fixed_versions = []
    for fixed_version in fixed_versions:
        try:
            fixed_version = vrc.version_class(fixed_version)
            parsed_fixed_versions.append(fixed_version.string)
        except Exception as e:
            logger(
                f"advisory_dict_to_advisory_data: fixed_version is not parsable`: {fixed_version!r} error: {e!r}\n {traceback.format_exc()}",
                level=logging.ERROR,
            )

    if affected_version_range:
        vrc = affected_version_range.__class__

    fixed_version_range = vrc.from_versions(parsed_fixed_versions)
    if not fixed_version_range and not affected_version_range:
        return

    purl_without_version = get_purl(
        package_slug=package_slug,
        purl_type_by_gitlab_scheme=purl_type_by_gitlab_scheme,
        logger=logger,
    )

    affected_package = AffectedPackageV2(
        package=purl_without_version,
        affected_version_range=affected_version_range,
        fixed_version_range=fixed_version_range,
    )

    if not advisory_url and package_slug and identifier:
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
