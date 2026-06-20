#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import time
import pytest
from pathlib import Path

from django.test import TestCase
from django.urls import reverse

from vulnerabilities.models import EPSS
from vulnerabilities.models import AdvisoryReference
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.pipelines.v2_importers.epss_importer_v2 import EPSSImporterPipeline
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
                datasource_id=EPSS.identifier,
                pipeline_id=EPSSImporterPipeline.pipeline_id,
                unique_content_id=f"hash_{i}",
            )

            advisory.references.add(ref_obj)

            for severity in data["severities"]:
                advisory.severities.create(
                    scoring_system=severity["system"],
                    value=severity["value"],
                    scoring_elements=severity["scoring_elements"],
                    published_at=severity["published_at"],
                )

            if i == 0:
                self.advisory = advisory

    @pytest.mark.ignore_template_errors()
    def test_epss_history_context(self):
        session = self.client.session
        session["altcha_verified_at"] = time.time()
        session.save()

        response = self.client.get(reverse("advisory_details", kwargs={"avid": self.advisory.avid}))
        self.assertEqual(response.status_code, 200)

        expected_file = Path(__file__).parent / "test_data" / "epss" / "epss_history_expected.json"
        history_data_for_json = [
            {**record, "published_at": record["published_at"].isoformat()}
            for record in response.context["epss_history_data"]
        ]

        check_results_against_json(history_data_for_json, expected_file)

    def test_get_epss_history(self):
        from vulnerabilities.views import get_epss_history

        epss_history_data, epss_pagination_obj = get_epss_history(self.advisory, 1)

        expected_file = Path(__file__).parent / "test_data" / "epss" / "epss_history_expected.json"
        history_data_for_json = [
            {**record, "published_at": record["published_at"].isoformat()}
            for record in epss_history_data
        ]

        check_results_against_json(history_data_for_json, expected_file)
        self.assertEqual(epss_pagination_obj.number, 1)
        self.assertTrue(epss_pagination_obj.has_next())
