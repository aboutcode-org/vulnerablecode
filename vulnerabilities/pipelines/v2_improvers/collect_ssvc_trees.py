#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from collections import defaultdict

from django.db.models import Prefetch
from django.db.models import Q

from vulnerabilities.models import SSVC
from vulnerabilities.models import AdvisorySeverity
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import PipelineSchedule
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.severity_systems import SCORING_SYSTEMS

logger = logging.getLogger(__name__)


class CollectSSVCPipeline(VulnerableCodePipeline):
    """
    Collect SSVC Pipeline

    This pipeline collects SSVC from Vulnrichment project and associates them with existing advisories.
    """

    pipeline_id = "collect_ssvc_trees"

    # Run pipeline every 30 minutes.
    run_interval = 30
    run_priority = PipelineSchedule.ExecutionPriority.HIGH

    @classmethod
    def steps(cls):
        return (cls.collect_ssvc_data,)

    def collect_ssvc_data(self):
        advisories = list(
            AdvisoryV2.objects.latest_per_avid()
            .filter(
                severities__scoring_system=SCORING_SYSTEMS["ssvc"],
            )
            .prefetch_related(
                Prefetch(
                    "severities",
                    queryset=AdvisorySeverity.objects.filter(
                        scoring_system=SCORING_SYSTEMS["ssvc"]
                    ).only("id", "scoring_elements"),
                ),
                "aliases",
            )
            .only("id", "advisory_id")
            .distinct()
        )

        self.log(f"Found {len(advisories)} advisories from Vulnrichment with SSVC severities.")
        advisory_ids = {a.advisory_id for a in advisories}

        all_related = (
            AdvisoryV2.objects.filter(
                Q(advisory_id__in=advisory_ids) | Q(aliases__alias__in=advisory_ids)
            )
            .distinct()
            .only("id", "advisory_id")
            .prefetch_related("aliases")
        )

        advisory_map = defaultdict(set)

        for adv in all_related:
            advisory_map[adv.advisory_id].add(adv)
            for alias in adv.aliases.all():
                if alias.alias in advisory_ids:
                    advisory_map[alias.alias].add(adv)

        existing_ssvc = {
            (s.source_advisory_id, s.vector): s
            for s in SSVC.objects.filter(source_advisory_id__in=[a.id for a in advisories])
        }

        self.log(f"Existing SSVC rows found: {len(existing_ssvc)}")
        self.log(f"Advisories to process: {len(advisories)}")

        to_create = []
        to_update = []

        for advisory in advisories:
            self.log(f"Processing advisory: {advisory.advisory_id}")

            for severity in advisory.severities.all():
                ssvc_vector = severity.scoring_elements

                try:
                    ssvc_tree, decision = convert_vector_to_tree_and_decision(ssvc_vector)

                    if not (ssvc_tree and decision):
                        continue

                    key = (advisory.id, ssvc_vector)

                    existing = existing_ssvc.get(key)

                    if existing:
                        existing.options = ssvc_tree
                        existing.decision = decision
                        existing.vector = ssvc_vector
                        to_update.append(existing)
                        ssvc_obj = existing
                    else:
                        ssvc_obj = SSVC(
                            source_advisory=advisory,
                            options=ssvc_tree,
                            decision=decision,
                            vector=ssvc_vector,
                        )
                        to_create.append(ssvc_obj)

                except Exception as e:
                    logger.error(
                        f"Failed to parse SSVC vector '{ssvc_vector}' "
                        f"for advisory '{advisory}': {e}"
                    )

        SSVC.objects.bulk_create(to_create, batch_size=1000)

        SSVC.objects.bulk_update(
            to_update,
            ["options", "decision", "vector"],
            batch_size=1000,
        )

        # Refresh newly created IDs
        created_ssvc = defaultdict(list)

        for s in SSVC.objects.filter(source_advisory_id__in=[a.id for a in advisories]):
            created_ssvc[s.source_advisory_id].append(s)

        through_model = SSVC.related_advisories.through

        through_rows = []

        for advisory in advisories:
            ssvc_objs = created_ssvc.get(advisory.id, [])

            related = advisory_map.get(advisory.advisory_id, set())

            for ssvc_obj in ssvc_objs:
                for related_adv in related:
                    if related_adv.id == advisory.id:
                        continue

                    through_rows.append(
                        through_model(
                            ssvc_id=ssvc_obj.id,
                            advisoryv2_id=related_adv.id,
                        )
                    )

        through_model.objects.bulk_create(
            through_rows,
            ignore_conflicts=True,
            batch_size=5000,
        )


REVERSE_POINTS = {
    "E": ("Exploitation", {"N": "none", "P": "poc", "A": "active"}),
    "A": ("Automatable", {"N": "no", "Y": "yes"}),
    "T": ("Technical Impact", {"P": "partial", "T": "total"}),
    "P": ("Mission Prevalence", {"M": "minimal", "S": "support", "E": "essential"}),
    "B": ("Public Well-being Impact", {"M": "minimal", "A": "material", "I": "irreversible"}),
    "M": ("Mission & Well-being", {"L": "low", "M": "medium", "H": "high"}),
}

REVERSE_DECISION = {
    "T": "Track",
    "R": "Track*",
    "A": "Attend",
    "C": "Act",
}

VECTOR_ORDER = ["E", "A", "T", "P", "B", "M"]


def convert_vector_to_tree_and_decision(vector: str):
    """
    Convert a given SSVC vector string into a structured tree and decision.

    Args:
        vector (str): The SSVC vector string.

    Returns:
        tuple: A tuple containing the SSVC tree (dict) and decision (str).
    """
    if not vector.startswith("SSVCv2/"):
        raise ValueError("Invalid SSVC vector")

    parts = [p for p in vector.replace("SSVCv2/", "").split("/") if p]

    options = []
    decision = None

    for part in parts:
        if ":" not in part:
            continue

        key, value = part.split(":", 1)

        if key == "D":
            decision = REVERSE_DECISION.get(value)
            continue

        if key in REVERSE_POINTS:
            name, mapping = REVERSE_POINTS[key]
            options.append({name: mapping[value]})

    options.sort(
        key=lambda o: (
            VECTOR_ORDER.index(next(k for k, _ in REVERSE_POINTS.values() if k == next(iter(o))))
            if False
            else 0
        )
    )

    return options, decision
