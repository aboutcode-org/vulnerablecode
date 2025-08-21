#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
#

import logging
from typing import Iterable

from packageurl import PackageURL
from univers.versions import GenericVersion
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
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

        if purl.name != "postgresql":
            raise ValueError(f"PURL: {purl!s} is expected to be for 'postgresql'")

        if not purl.version:
            raise ValueError(f"PURL: {purl!s} is expected to have a version")

        self.purl = purl

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        for advisory in super().collect_advisories():
            if self._advisory_affects_purl(advisory):
                yield advisory

    def _advisory_affects_purl(self, advisory: AdvisoryData) -> bool:
        if not advisory.affected_packages:
            return False

        try:
            package_semver_version = SemverVersion(self.purl.version)
            package_generic_version = GenericVersion(self.purl.version)
        except Exception as e:
            logger.debug(f"Invalid PURL version {self.purl.version!r}: {e}")
            return False

        for ap in advisory.affected_packages:
            if ap.package.type != "generic" or ap.package.name != "postgresql":
                continue

            purl_q = self.purl.qualifiers or None
            ap_q = ap.package.qualifiers or None

            if purl_q is None and ap_q is None:
                qualifiers_match = True
            else:
                qualifiers_match = all(ap_q.get(k) == v for k, v in purl_q.items())

            if not qualifiers_match:
                continue

            try:
                if getattr(ap, "affected_version_range", None):
                    if package_semver_version in ap.affected_version_range:
                        return True
                elif getattr(ap, "fixed_version", None):
                    if package_generic_version < ap.fixed_version:
                        return True
            except Exception as e:
                logger.debug(f"Version comparison failed for {package_semver_version}: {e}")
                continue

        return False
