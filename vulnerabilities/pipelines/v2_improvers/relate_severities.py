#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from itertools import batched

from django.db import transaction

from vulnerabilities.models import AdvisoryV2
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.pipelines.v2_importers.epss_importer_v2 import EPSSImporterPipeline
from vulnerabilities.pipelines.v2_importers.suse_score_importer import (
    SUSESeverityScoreImporterPipeline,
)
from vulnerabilities.severity_systems import CVSSV2
from vulnerabilities.severity_systems import CVSSV3
from vulnerabilities.severity_systems import CVSSV4
from vulnerabilities.severity_systems import CVSSV31
from vulnerabilities.severity_systems import EPSS

logger = logging.getLogger(__name__)


class RelateSeveritiesPipeline(VulnerableCodePipeline):
    """
    Severity Relations Pipeline: Relate EPSS and SUSE CVSS severities to advisories
    by matching severity advisory IDs with advisory IDs and aliases.
    """

    pipeline_id = "relate_severities_v2"

    # Severity systems to process
    SUPPORTED_SYSTEMS = {
        EPSS.identifier,
        CVSSV2.identifier,
        CVSSV3.identifier,
        CVSSV31.identifier,
        CVSSV4.identifier,
    }

    pipelines = [
        EPSSImporterPipeline.pipeline_id,
        SUSESeverityScoreImporterPipeline.pipeline_id,
    ]

    @classmethod
    def steps(cls):
        return (cls.relate_severities,)

    def relate_severities(self):
        """
        Relate EPSS and SUSE severities to advisories by matching advisory IDs.
        """
        # Filter severities by supported scoring systems
        severity_score_advisories = (
            AdvisoryV2.objects.filter(datasource_id__in=self.pipelines)
            .filter(severities__scoring_system__in=self.SUPPORTED_SYSTEMS)
            .distinct()
            .latest_per_avid()
        )

        total = severity_score_advisories.count()
        self.log(f"Processing {total:,d} advisories records")

        advisory_id_map = {}

        qs = AdvisoryV2.objects.filter(
            advisory_id__in=severity_score_advisories.values("advisory_id")
        ).values("id", "advisory_id")

        alias_qs = AdvisoryV2.objects.filter(
            aliases__alias__in=severity_score_advisories.values("advisory_id")
        ).values("id", "aliases__alias")

        for row in qs:
            advisory_id_map.setdefault(row["advisory_id"], set()).add(row["id"])

        for row in alias_qs:
            advisory_id_map.setdefault(row["aliases__alias"], set()).add(row["id"])

        through = AdvisoryV2.related_advisory_severities.through
        relations = []

        for advisory in severity_score_advisories:
            matches = advisory_id_map.get(advisory.advisory_id, set())
            for target_id in matches:
                if target_id != advisory.id:
                    self.log(f"Relating advisory {advisory.avid} to {target_id}")
                    relations.append(
                        through(
                            from_advisoryv2_id=target_id,
                            to_advisoryv2_id=advisory.id,
                        )
                    )

        BATCH_SIZE = 5000
        with transaction.atomic():
            for chunk in batched(relations, BATCH_SIZE):
                through.objects.bulk_create(chunk, ignore_conflicts=True)

        self.log(f"Successfully related {len(relations):,d} severities to advisories")
