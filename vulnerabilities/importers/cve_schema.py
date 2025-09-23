#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import json
import re

import dateparser

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerabilities.utils import get_cwe_id
from vulnerabilities.utils import get_reference_id
from vulnerabilities.utils import ssvc_calculator


def parse_cve_v5_advisory(raw_data, advisory_url):
    cve_metadata = raw_data.get("cveMetadata", {})
    cve_id = cve_metadata.get("cveId")

    date_published = cve_metadata.get("datePublished")
    if date_published:
        date_published = dateparser.parse(
            date_published,
            settings={
                "TIMEZONE": "UTC",
                "RETURN_AS_TIMEZONE_AWARE": True,
                "TO_TIMEZONE": "UTC",
            },
        )

    # Extract containers
    containers = raw_data.get("containers", {})
    cna_data = containers.get("cna", {})
    adp_data = containers.get("adp", {})

    # Extract descriptions
    summary = ""
    description_list = cna_data.get("descriptions", [])
    for description_dict in description_list:
        if not description_dict.get("lang") in ["en", "en-US"]:
            continue
        summary = description_dict.get("value")

    # Extract metrics
    severities = []
    metrics = cna_data.get("metrics", []) + [
        adp_metrics for data in adp_data for adp_metrics in data.get("metrics", [])
    ]

    cve_scoring_system = {
        "cvssV4_0": SCORING_SYSTEMS["cvssv4"],
        "cvssV3_1": SCORING_SYSTEMS["cvssv3.1"],
        "cvssV3_0": SCORING_SYSTEMS["cvssv3"],
        "cvssV2_0": SCORING_SYSTEMS["cvssv2"],
        "other": {
            "ssvc": SCORING_SYSTEMS["ssvc"],
        },  # ignore kev
    }

    for metric in metrics:
        for metric_type, metric_value in metric.items():
            if metric_type not in cve_scoring_system:
                continue

            if metric_type == "other":
                other_types = metric_value.get("type")
                if other_types == "ssvc":
                    content = metric_value.get("content", {})
                    vector_string, decision = ssvc_calculator(content)
                    scoring_system = cve_scoring_system[metric_type][other_types]
                    severity = VulnerabilitySeverity(
                        system=scoring_system, value=decision, scoring_elements=vector_string
                    )
                    severities.append(severity)
                # ignore kev
            else:
                vector_string = metric_value.get("vectorString")
                base_score = metric_value.get("baseScore")
                scoring_system = cve_scoring_system[metric_type]
                severity = VulnerabilitySeverity(
                    system=scoring_system, value=base_score, scoring_elements=vector_string
                )
                severities.append(severity)

    # Extract references cpes and ignore affected products
    cpes = set()
    for affected_product in cna_data.get("affected", []):
        if type(affected_product) != dict:
            continue
        cpes.update(affected_product.get("cpes") or [])

    references = []
    for ref in cna_data.get("references", []):
        # https://github.com/CVEProject/cve-schema/blob/main/schema/tags/reference-tags.json
        # We removed all unwanted reference types and set the default reference type to 'OTHER'.
        ref_type = VulnerabilityReference.OTHER
        vul_ref_types = {
            "exploit": VulnerabilityReference.EXPLOIT,
            "issue-tracking": VulnerabilityReference.BUG,
            "mailing-list": VulnerabilityReference.MAILING_LIST,
            "third-party-advisory": VulnerabilityReference.ADVISORY,
            "vendor-advisory": VulnerabilityReference.ADVISORY,
            "vdb-entry": VulnerabilityReference.ADVISORY,
        }

        for tag_type in ref.get("tags", []):
            if tag_type in vul_ref_types:
                ref_type = vul_ref_types.get(tag_type)

        url = ref.get("url")
        reference = ReferenceV2(
            reference_id=get_reference_id(url),
            url=url,
            reference_type=ref_type,
        )

        references.append(reference)

    cpes_ref = [
        ReferenceV2(
            reference_id=cpe,
            reference_type=VulnerabilityReference.OTHER,
            url=f"https://nvd.nist.gov/vuln/search/results?adv_search=true&isCpeNameSearch=true&query={cpe}",
        )
        for cpe in sorted(list(cpes))
    ]
    references.extend(cpes_ref)

    weaknesses = set()
    for problem_type in cna_data.get("problemTypes", []):
        descriptions = problem_type.get("descriptions", [])
        for description in descriptions:
            cwe_id = description.get("cweId")
            if cwe_id:
                weaknesses.add(get_cwe_id(cwe_id))

            description_text = description.get("description")
            if description_text:
                pattern = r"CWE-(\d+)"
                match = re.search(pattern, description_text)
                if match:
                    weaknesses.add(int(match.group(1)))

    return AdvisoryData(
        advisory_id=cve_id,
        aliases=[],
        summary=summary,
        references_v2=references,
        date_published=date_published,
        weaknesses=sorted(weaknesses),
        url=advisory_url,
        severities=severities,
        original_advisory_text=json.dumps(raw_data, indent=2, ensure_ascii=False),
    )
