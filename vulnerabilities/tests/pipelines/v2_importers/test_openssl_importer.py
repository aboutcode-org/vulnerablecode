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

from django.test import TestCase

from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import PackageV2
from vulnerabilities.pipelines.v2_importers.openssl_importer import OpenSSLImporterPipeline
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "openssl" / "release_metadata"


class TestOpenSSLImporterPipeline(TestCase):
    @patch("vulnerabilities.pipelines.v2_importers.openssl_importer.OpenSSLImporterPipeline.clone")
    def test_redhat_advisories_v2(self, mock_clone):
        mock_clone.__name__ = "clone"
        pipeline = OpenSSLImporterPipeline()
        pipeline.advisory_path = TEST_DATA
        pipeline.vcs_response = None
        pipeline.execute()

        # self.assertEqual(6, AdvisoryV2.objects.count())
        # self.assertEqual(93, PackageV2.objects.count())

        expected_file = TEST_DATA / "openssl_advisoryv2-expected.json"
        result = [adv.to_advisory_data() for adv in AdvisoryV2.objects.all()]
        print(result)
        # util_tests.check_results_against_json(result, expected_file, regen=True)
