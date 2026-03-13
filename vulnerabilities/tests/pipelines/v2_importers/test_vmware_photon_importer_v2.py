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
from unittest import TestCase
from unittest.mock import Mock
from unittest.mock import patch

from vulnerabilities.pipelines.v2_importers.vmware_photon_importer_v2 import (
    VmwarePhotonImporterPipeline,
)
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "vmware_photon"


class TestVmwarePhotonImporterPipeline(TestCase):
    @patch("vulnerabilities.pipelines.v2_importers.vmware_photon_importer_v2.fetch_response")
    def test_collect_advisories(self, mock_fetch):
        sample_path = TEST_DATA / "data.json"
        sample_data = json.loads(sample_path.read_text(encoding="utf-8"))

        index_html = """
        <a href="cve_data_photon4.0.json">cve_data_photon4.0.json</a>
        """

        def side_effect(url):
            if url == "https://packages.vmware.com/photon/photon_cve_metadata/":
                return Mock(text=index_html)
            if "cve_data_photon4.0.json" in url:
                return Mock(json=lambda: sample_data)
            return None

        mock_fetch.side_effect = side_effect

        pipeline = VmwarePhotonImporterPipeline()
        pipeline.fetch()
        pipeline.group_records_by_cve()

        advisories = [data.to_dict() for data in list(pipeline.collect_advisories())]
        assert len(advisories) == 2

        expected_file = TEST_DATA / "expected.json"
        util_tests.check_results_against_json(advisories, expected_file)
