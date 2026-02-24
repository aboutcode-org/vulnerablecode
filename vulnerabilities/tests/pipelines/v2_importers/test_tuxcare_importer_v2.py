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

from vulnerabilities.pipelines.v2_importers.tuxcare_importer import TuxCareImporterPipeline
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "tuxcare"


class TestTuxCareImporterPipeline(TestCase):
    @patch("vulnerabilities.pipelines.v2_importers.tuxcare_importer.fetch_response")
    def test_collect_advisories(self, mock_fetch):
        sample_path = TEST_DATA / "data.json"
        sample_data = json.loads(sample_path.read_text(encoding="utf-8"))

        mock_fetch.return_value = Mock(json=lambda: sample_data)

        pipeline = TuxCareImporterPipeline()
        pipeline.fetch()
        pipeline.group_records_by_cve()

        advisories = [data.to_dict() for data in list(pipeline.collect_advisories())]

        expected_file = TEST_DATA / "expected.json"
        util_tests.check_results_against_json(advisories, expected_file)

        assert len(advisories) == 14

    def test_create_purl(self):
        pipeline = TuxCareImporterPipeline()

        cases = [
            ("squid", "CloudLinux 7 ELS", "rpm", "cloudlinux", "cloudlinux-7-els"),
            ("squid", "Oracle Linux 7 ELS", "rpm", "oracle", "oracle-linux-7-els"),
            ("kernel", "CentOS 8.5 ELS", "rpm", "centos", "centos-8.5-els"),
            ("squid", "CentOS Stream 8 ELS", "rpm", "centos", "centos-stream-8-els"),
            ("libpng", "CentOS 7 ELS", "rpm", "centos", "centos-7-els"),
            ("java-11-openjdk", "RHEL 7 ELS", "rpm", "rhel", "rhel-7-els"),
            ("mysql", "AlmaLinux 9.2 ESU", "rpm", "almalinux", "almalinux-9.2-esu"),
            ("linux", "Ubuntu 16.04 ELS", "deb", "ubuntu", "ubuntu-16.04-els"),
            ("samba", "Debian 10 ELS", "deb", "debian", "debian-10-els"),
            ("dpkg", "Alpine Linux 3.18 ELS", "apk", "alpine", "alpine-linux-3.18-els"),
            ("kernel", "Unknown OS", "generic", "tuxcare", "unknown-os"),
            ("webkit2gtk3", "TuxCare 9.6 ESU", "generic", "tuxcare", "tuxcare-9.6-esu"),
        ]

        for name, os_name, expected_type, expected_ns, expected_distro in cases:
            purl = pipeline._create_purl(name, os_name)
            assert purl is not None, f"Expected purl for os_name={os_name!r}"
            assert purl.type == expected_type
            assert purl.namespace == expected_ns
            assert purl.qualifiers == {"distro": expected_distro}

        # Invalid PURL
        assert pipeline._create_purl("foo", "Foo 123") is None
