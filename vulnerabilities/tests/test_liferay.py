#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
from unittest import TestCase
from unittest.mock import MagicMock
from unittest.mock import patch

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.pipelines.v2_importers.liferay_importer import LiferayImporterPipeline

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data")


class TestLiferayImporterPipeline(TestCase):
    @patch("vulnerabilities.pipelines.v2_importers.liferay_importer.requests.get")
    def test_collect_advisories(self, mock_get):
        importer = LiferayImporterPipeline()

        # Mock responses
        mock_main_page = MagicMock()
        mock_main_page.content = b"""
        <html>
            <body>
                <a href="/portal/security/known-vulnerabilities/-/categories/12345">Liferay Portal 7.4</a>
            </body>
        </html>
        """

        mock_release_page = MagicMock()
        mock_release_page.content = b"""
        <html>
            <body>
                <a href="/portal/security/known-vulnerabilities/-/asset_publisher/jekt/content/cve-2023-1234">CVE-2023-1234 Title</a>
            </body>
        </html>
        """

        mock_vuln_page = MagicMock()
        mock_vuln_page.content = b"""
        <html>
            <body>
                <h1>CVE-2023-1234 Title</h1>
                <h3>Description</h3>
                <p>This is a test vulnerability description.</p>
                <h3>Severity</h3>
                <p>4.8 (CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N)</p>
                <h3>Affected Version(s)</h3>
                <ul>
                    <li>Liferay Portal 7.4.0</li>
                </ul>
            </body>
        </html>
        """

        # Configure side_effect to return different mocks based on URL
        def side_effect(url):
            if url == "https://liferay.dev/portal/security/known-vulnerabilities":
                return mock_main_page
            elif "categories" in url:
                return mock_release_page
            elif "asset_publisher" in url:
                return mock_vuln_page
            return MagicMock()

        mock_get.side_effect = side_effect

        advisories = list(importer.collect_advisories())

        self.assertEqual(len(advisories), 1)
        advisory = advisories[0]
        self.assertIsInstance(advisory, AdvisoryData)
        self.assertEqual(advisory.aliases, [])
        self.assertEqual(advisory.summary, "This is a test vulnerability description.")
        self.assertEqual(len(advisory.affected_packages), 1)
        self.assertEqual(advisory.affected_packages[0].package.name, "liferay-portal")
