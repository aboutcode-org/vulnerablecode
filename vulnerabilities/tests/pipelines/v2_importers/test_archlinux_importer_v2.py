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
from unittest import TestCase

from vulnerabilities.pipelines.v2_importers.archlinux_importer import ArchLinuxImporterPipeline
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "archlinux"


class TestArchLinuxImporterPipeline(TestCase):
    def test_to_archlinux_advisories_v2(self):
        archlinux_advisory_path = TEST_DATA / "archlinux-multi.json"

        data = json.loads(archlinux_advisory_path.read_text(encoding="utf-8"))
        expected_file = os.path.join(TEST_DATA, "archlinux_advisoryv2-expected.json")
        pipeline = ArchLinuxImporterPipeline()
        pipeline.response = data
        result = [adv.to_dict() for adv in pipeline.collect_advisories()]
        util_tests.check_results_against_json(result, expected_file)
