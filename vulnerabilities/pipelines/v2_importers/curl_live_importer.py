#
# Copyright (c) nexB Inc. and others. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

import logging
from typing import Iterable

from packageurl import PackageURL
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.pipelines.v2_importers.curl_importer import CurlImporterPipeline

logger = logging.getLogger(__name__)


class CurlLiveImporterPipeline(CurlImporterPipeline):
    """
    Pipeline-based importer for curl advisories from curl.se for a single PURL.
    """

    pipeline_id = "curl_live_importer_v2"
    supported_types = ["generic"]

    @classmethod
    def steps(cls):
        return (
            cls.get_purl_inputs,
            cls.collect_and_store_advisories,
        )

    def get_purl_inputs(self):
        purl = self.inputs["purl"]
        if not purl:
            raise ValueError("PURL is required for CurlLiveImporterPipeline")

        if isinstance(purl, str):
            purl = PackageURL.from_string(purl)

        if not isinstance(purl, PackageURL):
            raise ValueError(f"Object of type {type(purl)} {purl!r} is not a PackageURL instance")

        if purl.type not in self.supported_types:
            raise ValueError(
                f"PURL: {purl!s} is not among the supported package types {self.supported_types!r}"
            )

        if purl.name != "curl" or purl.namespace != "curl.se":
            raise ValueError(f"PURL: {purl!s} is expected to be for curl")

        if not purl.version:
            raise ValueError(f"PURL: {purl!s} is expected to have a version")

        self.purl = purl

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        for advisory in super().collect_advisories():
            if self._advisory_affects_purl(advisory):
                yield advisory

    def _advisory_affects_purl(self, advisory: AdvisoryData) -> bool:
        for affected_package in advisory.affected_packages:
            if affected_package.package.name != "curl":
                continue

            if affected_package.affected_version_range:
                try:
                    purl_version = SemverVersion(self.purl.version)

                    if purl_version not in affected_package.affected_version_range:
                        continue
                except Exception as e:
                    logger.error(f"Error checking version {self.purl.version}: {e}")
                    continue

            return True

        return False
