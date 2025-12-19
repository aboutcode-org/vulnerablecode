#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import json
from pathlib import Path

from fetchcode.vcs import fetch_via_vcs

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.models import AdvisoryToDoV2
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.pipes.advisory import insert_advisory_v2


class CurateAdvisoriesPipeline(VulnerableCodePipeline):
    """
    Curate advisories
    """

    pipeline_id = "curate_advisories"
    license_expression = None

    """
    Sample Curation Advisory:

    {
    advisory: {
    "advisory_id": "CVE-2024-12345",
    "summary": "This is a curated summary for CVE-2024-12345",
    "url": "https://github.com/TG1999/CVE-2024-12345",
    "aliases": ["GHSA-1323-1213"],
    "references": [
            {
                "url": "https://github.com/TG1999/CVE-2024-12345",
                "reference_id": "CVE-2024-12345",
            }
        ],
    "severity": [
        {
            "system": "CVSSv3",
            "value": "9.8",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }
    ],
    "affected_packages": [
    {
        "package": {
        "type": "pypi",
        "namespace": null,
        "name": "example-package",
        "version": "1.0.0"
        },
        "affected_version_range": "<=1.0.0",
        "fixed_version": "1.0.1"
    },
    ]
    },
    related_advisories: ["nvd_importer_v2/CVE-2024-12345"],
    todo_ids : [133],
    source: "Tushar",
    }
    """

    @classmethod
    def steps(cls):
        return (
            cls.fetch_curation_repo,
            cls.apply_curations,
        )

    @classmethod
    def fetch_curation_repo(self):
        """
        Fetch curation repository
        """
        self.vcs_response = fetch_via_vcs(self.repo_url)

    @classmethod
    def apply_curations(self):
        """
        Apply curation to advisories
        """
        advisory_files = Path(self.vcs_response.dest_dir).rglob("*.json")
        for advisory_file in advisory_files:
            advisory_data = json.load(open(advisory_file))
            advisory = AdvisoryData.from_dict(advisory_data["advisory"])
            advisory_obj = insert_advisory_v2(advisory=advisory, source=advisory_data.get("source"))
            # Link related advisories
            for related_advisory_id in advisory_data.get("related_advisories", []):
                related_advisory = AdvisoryV2.objects.filter(avid=related_advisory_id).first()
                if related_advisory:
                    advisory_obj.related_advisories.add(related_advisory)
            advisory_obj.save()

            for todo in AdvisoryToDoV2.objects.filter(id__in=advisory_data.get("todo_ids", [])):
                # Add advisory in todo's curated_advisories field
                todo.curated_advisories.add(advisory_obj)
                todo.save()
