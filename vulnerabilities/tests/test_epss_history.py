import json
from pathlib import Path

from django.test import TestCase
from django.urls import reverse

from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import AdvisoryReference
from vulnerabilities.models import AdvisorySeverity
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.tests.util_tests import check_results_against_json


class AdvisoryDetailsEpssTestCase(TestCase):
    def setUp(self):
        json_file = Path(__file__).parent / "test_data" / "epss" / "epss_history_test_data.json"
        with open(json_file, "r") as f:
            json_data = json.load(f)

        ref_obj = AdvisoryReference.objects.create(url=json_data[0]["references"][0]["url"])

        for i, data in enumerate(json_data):
            is_latest = i == 0

            advisory = AdvisoryV2.objects.create(
                avid=f"test_epss/advisory-{i}",
                advisory_id="CVE-2022-25204",
                url="https://epss.cyentia.com/epss_scores-current.csv.gz",
                is_latest=is_latest,
                datasource_id="test_epss",
                pipeline_id="test_epss",
                unique_content_id=f"hash_{i}",
            )

            advisory.references.add(ref_obj)

            severity = data["severities"][0]
            advisory.severities.create(
                scoring_system=severity["system"],
                value=severity["value"],
                scoring_elements=severity["scoring_elements"],
                published_at=severity["published_at"],
            )

            if i == 0:
                self.advisory = advisory

    def test_epss_history_context(self):
        response = self.client.get(reverse("advisory_details", kwargs={"avid": self.advisory.avid}))
        self.assertEqual(response.status_code, 200)

        expected_file = Path(__file__).parent / "test_data" / "epss" / "epss_history_expected.json"
        history_data_for_json = [
            {**record, "published_at": record["published_at"].isoformat()}
            for record in response.context["epss_history_data"]
        ]

        check_results_against_json(history_data_for_json, expected_file)
