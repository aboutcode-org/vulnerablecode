#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging

from django.db.models import Q
from vulnerabilities.models import SSVC
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.pipelines.v2_importers.vulnrichment_importer import VulnrichImporterPipeline
from vulnerabilities.severity_systems import SCORING_SYSTEMS

logger = logging.getLogger(__name__)


class CollectSSVCPipeline(VulnerableCodePipeline):
    """
    Collect SSVC Pipeline

    This pipeline collects SSVC from Vulnrichment project and associates them with existing advisories.
    """

    pipeline_id = "collect_ssvc_tree_v2"
    spdx_license_expression = "CC0-1.0"

    @classmethod
    def steps(cls):
        return (
            cls.collect_ssvc_data,
        )

    def collect_ssvc_data(self):
        vulnrichment_advisories = AdvisoryV2.objects.filter(
            datasource_id=VulnrichImporterPipeline.pipeline_id,
        )
        for advisory in vulnrichment_advisories:
            severities = advisory.severities.filter(scoring_system=SCORING_SYSTEMS["ssvc"])
            for severity in severities:
                ssvc_vector = severity.scoring_elements
                try:
                    ssvc_tree, decision = convert_vector_to_tree_and_decision(ssvc_vector)
                    self.log(f"Advisory: {advisory.advisory_id}, SSVC Tree: {ssvc_tree}, Decision: {decision}, vector: {ssvc_vector}")
                    ssvc_obj, _ = SSVC.objects.get_or_create(
                        source_advisory=advisory,
                        defaults={
                            "options": ssvc_tree,
                            "decision": decision,
                        },
                    )
                    # All advisories that have advisory.advisory_id in their aliases or advisory_id same as advisory.advisory_id
                    related_advisories = AdvisoryV2.objects.filter(
                        Q(advisory_id=advisory.advisory_id) |
                        Q(aliases__alias=advisory.advisory_id)
                    ).distinct()
                    # remove the current advisory from related advisories
                    related_advisories = related_advisories.exclude(id=advisory.id)
                    ssvc_obj.related_advisories.set(related_advisories)
                except ValueError as e:
                    logger.error(f"Failed to parse SSVC vector '{ssvc_vector}' for advisory '{advisory}': {e}")

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

    # Preserve canonical SSVC order
    options.sort(key=lambda o: VECTOR_ORDER.index(
        next(k for k, _ in REVERSE_POINTS.values() if k == next(iter(o)))
    ) if False else 0)

    return options, decision
