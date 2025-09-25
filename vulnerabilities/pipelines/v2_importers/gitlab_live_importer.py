#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from typing import Iterable

from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.pipelines.v2_importers.gitlab_advisory_utils import (
    advisory_dict_to_advisory_data as shared_advisory_dict_to_advisory_data,
)
from vulnerabilities.pipelines.v2_importers.gitlab_importer import get_purl
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

        for advisory in advisories:
            advisory_data = self._advisory_dict_to_advisory_data(advisory)
            if not advisory_data:
                continue
            # Filter by the input version: keep only advisories where the given version is affected
            from univers.version_range import RANGE_CLASS_BY_SCHEMES

            input_version = self.purl.version
            vrc = RANGE_CLASS_BY_SCHEMES[self.purl.type]
            version_obj = vrc.version_class(input_version) if input_version else None

            affected = False
            for affected_package in advisory_data.affected_packages:
                vrange = affected_package.affected_version_range
                if vrange and version_obj in vrange:
                    affected = True
                    break
            if affected:
                yield advisory_data

    def _advisory_dict_to_advisory_data(self, advisory):
        return shared_advisory_dict_to_advisory_data(
            advisory=advisory,
            purl_type_by_gitlab_scheme=self.purl_type_by_gitlab_scheme,
            gitlab_scheme_by_purl_type=self.gitlab_scheme_by_purl_type,
            logger=self.log,
            get_purl_fn=get_purl,
            purl=self.purl,
        )
