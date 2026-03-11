#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


from pathlib import Path
from unittest.mock import patch

from bs4 import BeautifulSoup
from django.test import TestCase

from vulnerabilities.models import AdvisoryV2
from vulnerabilities.pipelines.v2_importers.apache_kafka_importer import ApacheKafkaImporterPipeline
from vulnerabilities.tests import util_tests
from vulnerabilities.tests.pipelines import TestLogger

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "apache_kafka"


class TestApacheKafkaImporterPipeline(TestCase):
    def setUp(self):
        self.logger = TestLogger()

    @patch(
        "vulnerabilities.pipelines.v2_importers.apache_kafka_importer.ApacheKafkaImporterPipeline.fetch"
    )
    def test_redhat_advisories_v2(self, mock_fetch):
        mock_fetch.__name__ = "fetch"
        cve_list = TEST_DATA / "cve-list-2026_01_23.html"
        advisory_data = open(cve_list).read()

        pipeline = ApacheKafkaImporterPipeline()
        pipeline.soup = BeautifulSoup(advisory_data, features="lxml")
        pipeline.log = self.logger.write
        pipeline.execute()

        expected_file = TEST_DATA / "cve-list-2026_01_23-expected.json"
        result = [adv.to_advisory_data().to_dict() for adv in AdvisoryV2.objects.all()]
        util_tests.check_results_against_json(result, expected_file)
