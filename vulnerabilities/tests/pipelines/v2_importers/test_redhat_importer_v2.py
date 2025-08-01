#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import os
from pathlib import Path
from unittest.mock import Mock
from unittest.mock import patch

from django.test import TestCase

from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import PackageV2
from vulnerabilities.pipelines.v2_importers.redhat_importer import RedHatImporterPipeline
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "redhat" / "csaf_2_0"


class TestArchLinuxImporterPipeline(TestCase):
    @patch("vulnerabilities.pipelines.v2_importers.redhat_importer.RedHatImporterPipeline.fetch")
    def test_redhat_advisories_v2(self, mock_fetch):
        mock_fetch.__name__ = "fetch"
        pipeline = RedHatImporterPipeline()
        pipeline.location = TEST_DATA
        pipeline.execute()
        self.assertEqual(6, AdvisoryV2.objects.count())
        self.assertEqual(93, PackageV2.objects.count())
        expected_file = TEST_DATA.parent / "redhat_advisoryv2-expected.json"
        result = [adv.to_advisory_data().to_dict() for adv in AdvisoryV2.objects.all()]
        util_tests.check_results_against_json(result, expected_file)
