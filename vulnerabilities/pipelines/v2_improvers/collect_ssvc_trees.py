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
from itertools import batched

from vulnerabilities.models import SSVC
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import PipelineSchedule
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.severity_systems import SCORING_SYSTEMS

logger = logging.getLogger(__name__)


class CollectSSVCPipeline(VulnerableCodePipeline):
    """
    Collect SSVC Pipeline

    This pipeline collects SSVC from the Vulnrichment project and associates them with
    existing advisories.
    """

    pipeline_id = "collect_ssvc_trees"

    # Run pipeline every 30 minutes.
    run_interval = 30
    run_priority = PipelineSchedule.ExecutionPriority.HIGH

    batch_size = 1000
    through_batch_size = 5000

    @classmethod
    def steps(cls):
        return (cls.collect_ssvc_data,)

    def collect_ssvc_data(self):
        advisory_pairs = list(
            AdvisoryV2.objects.latest_per_avid()
            .filter(severities__scoring_system=SCORING_SYSTEMS["ssvc"])
            .values_list("id", "advisory_id")
            .distinct()
            .order_by("id")
        )

        self.log(f"Found {len(advisory_pairs)} advisories from Vulnrichment with SSVC severities.")
        if not advisory_pairs:
            return

        created_count = 0
        updated_count = 0

        for batch in batched(advisory_pairs, self.batch_size):
            created, updated = self._process_batch(batch)
            created_count += created
            updated_count += updated

        self.log(
            f"Processed {len(advisory_pairs)} advisories: "
            f"created {created_count}, updated {updated_count} SSVC rows."
        )

    def _process_batch(self, batch):
        batch_pks = [pk for pk, _ in batch]
        batch_advisory_ids = {advisory_id for _, advisory_id in batch}

        severities_by_advisory = defaultdict(list)
        for adv_pk, scoring_elements in AdvisoryV2.severities.through.objects.filter(
            advisoryv2_id__in=batch_pks,
            advisoryseverity__scoring_system=SCORING_SYSTEMS["ssvc"],
        ).values_list("advisoryv2_id", "advisoryseverity__scoring_elements"):
            severities_by_advisory[adv_pk].append(scoring_elements)

        advisory_map = defaultdict(set)
        for adv_id, pk in AdvisoryV2.objects.filter(advisory_id__in=batch_advisory_ids).values_list(
            "advisory_id", "id"
        ):
            advisory_map[adv_id].add(pk)

        for alias, pk in AdvisoryV2.aliases.through.objects.filter(
            advisoryalias__alias__in=batch_advisory_ids
        ).values_list("advisoryalias__alias", "advisoryv2_id"):
            advisory_map[alias].add(pk)

        existing_ssvc = {
            (s.source_advisory_id, s.vector): s
            for s in SSVC.objects.filter(source_advisory_id__in=batch_pks)
        }

        to_create = []
        to_update = []
        seen_keys = set()

        for adv_pk, advisory_id in batch:
            for ssvc_vector in severities_by_advisory.get(adv_pk, ()):
                try:
                    ssvc_tree, decision = convert_vector_to_tree_and_decision(ssvc_vector)

                    if not (ssvc_tree and decision):
                        continue

                    key = (adv_pk, ssvc_vector)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)

                    existing = existing_ssvc.get(key)

                    if existing:
                        if existing.options != ssvc_tree or existing.decision != decision:
                            existing.options = ssvc_tree
                            existing.decision = decision
                            to_update.append(existing)
                    else:
                        to_create.append(
                            SSVC(
                                source_advisory_id=adv_pk,
                                options=ssvc_tree,
                                decision=decision,
                                vector=ssvc_vector,
                            )
                        )

                except Exception as e:
                    logger.error(
                        f"Failed to parse SSVC vector '{ssvc_vector}' "
                        f"for advisory '{advisory_id}': {e}"
                    )

        if to_create:
            SSVC.objects.bulk_create(to_create, batch_size=self.batch_size)

        if to_update:
            SSVC.objects.bulk_update(
                to_update,
                ["options", "decision"],
                batch_size=self.batch_size,
            )

        ssvc_ids_by_advisory = defaultdict(list)
        if to_create:
            for source_advisory_id, ssvc_id in SSVC.objects.filter(
                source_advisory_id__in=batch_pks
            ).values_list("source_advisory_id", "id"):
                ssvc_ids_by_advisory[source_advisory_id].append(ssvc_id)
        else:
            for ssvc_obj in existing_ssvc.values():
                ssvc_ids_by_advisory[ssvc_obj.source_advisory_id].append(ssvc_obj.id)

        through_model = SSVC.related_advisories.through
        through_rows = []

        for adv_pk, advisory_id in batch:
            ssvc_ids = ssvc_ids_by_advisory.get(adv_pk)
            if not ssvc_ids:
                continue

            related_pks = advisory_map.get(advisory_id)
            if not related_pks:
                continue

            for ssvc_id in ssvc_ids:
                for related_pk in related_pks:
                    if related_pk == adv_pk:
                        continue

                    through_rows.append(
                        through_model(
                            ssvc_id=ssvc_id,
                            advisoryv2_id=related_pk,
                        )
                    )
                    if len(through_rows) >= self.through_batch_size:
                        through_model.objects.bulk_create(
                            through_rows,
                            ignore_conflicts=True,
                            batch_size=self.through_batch_size,
                        )
                        through_rows.clear()

        if through_rows:
            through_model.objects.bulk_create(
                through_rows,
                ignore_conflicts=True,
                batch_size=self.through_batch_size,
            )

        return len(to_create), len(to_update)


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
