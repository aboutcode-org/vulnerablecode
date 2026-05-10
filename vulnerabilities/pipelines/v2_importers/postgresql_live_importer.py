#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
#

import logging
from typing import Iterable

from packageurl import PackageURL
from univers.versions import InvalidVersion
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.pipelines.v2_importers.postgresql_importer import PostgreSQLImporterPipeline

logger = logging.getLogger(__name__)


class PostgreSQLLiveImporterPipeline(PostgreSQLImporterPipeline):
    """
    Live importer for PostgreSQL that filters the batch output to a single PURL.
    """

    pipeline_id = "postgresql_live_importer_v2"
    supported_types = ["generic"]

    @classmethod
    def steps(cls):
        return (
            cls.get_purl_inputs,
            cls.collect_and_store_advisories,
        )

    def get_purl_inputs(self):
        purl = self.inputs.get("purl")
        if not purl:
            raise ValueError("PURL is required for PostgreSQLLiveImporterPipeline")

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

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        for advisory in super().collect_advisories():
            if self._advisory_related_purl(advisory):
                yield advisory

    def _advisory_related_purl(self, advisory: AdvisoryDataV2) -> bool:
        if not advisory.affected_packages:
            return False

        try:
            package_version = SemverVersion(self.purl.version)
        except InvalidVersion as e:
            logger.debug(f"Invalid PURL version {self.purl.version!r}: {e}")
            return False

        for ap in advisory.affected_packages:
            if (ap.affected_version_range and package_version in ap.affected_version_range) or (
                ap.fixed_version_range and package_version in ap.fixed_version_range
            ):
                return True

        return False
