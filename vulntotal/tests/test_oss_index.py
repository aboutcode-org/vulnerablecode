#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import os
from pathlib import Path
from unittest import mock

import requests
from commoncode import testcase
from packageurl import PackageURL

from vulnerabilities.tests import util_tests
from vulntotal.datasources import oss_index


class TestSonatypeGuide(testcase.FileBasedTesting):
    test_data_dir = str(Path(__file__).resolve().parent / "test_data" / "oss_index")

    def setUp(self):
        super().setUp()
        patcher = mock.patch("vulntotal.datasources.oss_index.load_dotenv")
        self.mock_load_dotenv = patcher.start()
        self.addCleanup(patcher.stop)

    def test_parse_advisory(self):
        advisory_file = self.get_test_loc("advisory.json")
        with open(advisory_file) as f:
            advisory = json.load(f)
        results = [
            adv.to_dict()
            for adv in oss_index.parse_advisory(
                advisory, PackageURL("generic", "namespace", "test")
            )
        ]
        expected_file = self.get_test_loc("parse_advisory-expected.json", must_exist=False)
        util_tests.check_results_against_json(results, expected_file)

    @mock.patch.dict(os.environ, {}, clear=True)
    @mock.patch("requests.post")
    def test_fetch_json_response_unauthenticated(self, mock_post):
        mock_response = mock.MagicMock()
        mock_response.json.return_value = [{"coordinates": "pkg:npm/foo@1.0"}]
        mock_post.return_value = mock_response

        ds = oss_index.SonatypeGuideDataSource()
        result = ds.fetch_json_response(["pkg:npm/foo@1.0"])

        mock_post.assert_called_once_with(
            "https://api.guide.sonatype.com/api/v3/component-report",
            auth=None,
            json={"coordinates": ["pkg:npm/foo@1.0"]},
        )
        assert result == [{"coordinates": "pkg:npm/foo@1.0"}]

    @mock.patch.dict(os.environ, {"SONATYPE_GUIDE_TOKEN": "test-pat-123"}, clear=True)
    @mock.patch("requests.post")
    def test_fetch_json_response_with_pat_only(self, mock_post):
        mock_response = mock.MagicMock()
        mock_response.json.return_value = [{"coordinates": "pkg:npm/foo@1.0"}]
        mock_post.return_value = mock_response

        ds = oss_index.SonatypeGuideDataSource()
        result = ds.fetch_json_response(["pkg:npm/foo@1.0"])

        mock_post.assert_called_once_with(
            "https://api.guide.sonatype.com/api/v3/authorized/component-report",
            auth=("token", "test-pat-123"),
            json={"coordinates": ["pkg:npm/foo@1.0"]},
        )
        assert result == [{"coordinates": "pkg:npm/foo@1.0"}]

    @mock.patch.dict(
        os.environ,
        {"SONATYPE_GUIDE_USERNAME": "developer@example.com", "SONATYPE_GUIDE_TOKEN": "test-pat-123"},
        clear=True,
    )
    @mock.patch("requests.post")
    def test_fetch_json_response_with_username_and_pat(self, mock_post):
        mock_response = mock.MagicMock()
        mock_response.json.return_value = [{"coordinates": "pkg:npm/foo@1.0"}]
        mock_post.return_value = mock_response

        ds = oss_index.SonatypeGuideDataSource()
        result = ds.fetch_json_response(["pkg:npm/foo@1.0"])

        mock_post.assert_called_once_with(
            "https://api.guide.sonatype.com/api/v3/authorized/component-report",
            auth=("developer@example.com", "test-pat-123"),
            json={"coordinates": ["pkg:npm/foo@1.0"]},
        )
        assert result == [{"coordinates": "pkg:npm/foo@1.0"}]

    @mock.patch.dict(
        os.environ,
        {"OSS_USERNAME": "legacy@example.com", "OSS_TOKEN": "legacy-token"},
        clear=True,
    )
    @mock.patch("requests.post")
    def test_fetch_json_response_legacy_env_fallback(self, mock_post):
        mock_response = mock.MagicMock()
        mock_response.json.return_value = [{"coordinates": "pkg:npm/foo@1.0"}]
        mock_post.return_value = mock_response

        ds = oss_index.OSSDataSource()
        result = ds.fetch_json_response(["pkg:npm/foo@1.0"])

        mock_post.assert_called_once_with(
            "https://api.guide.sonatype.com/api/v3/authorized/component-report",
            auth=("legacy@example.com", "legacy-token"),
            json={"coordinates": ["pkg:npm/foo@1.0"]},
        )
        assert result == [{"coordinates": "pkg:npm/foo@1.0"}]

    @mock.patch.dict(os.environ, {}, clear=True)
    @mock.patch("requests.post")
    def test_fetch_json_response_401_unauthenticated(self, mock_post):
        mock_response = mock.MagicMock()
        mock_response.status_code = 401
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            response=mock_response
        )
        mock_post.return_value = mock_response

        ds = oss_index.SonatypeGuideDataSource()
        with self.assertLogs("vulntotal.datasources.oss_index", level="ERROR") as cm:
            assert ds.fetch_json_response(["pkg:npm/foo@1.0"]) is None
            assert any(
                "Sonatype Guide requires a token: set SONATYPE_GUIDE_TOKEN in your environment or .env"
                in msg
                for msg in cm.output
            )

    @mock.patch.dict(os.environ, {"SONATYPE_GUIDE_TOKEN": "bad-token"}, clear=True)
    @mock.patch("requests.post")
    def test_fetch_json_response_401_authenticated(self, mock_post):
        mock_response = mock.MagicMock()
        mock_response.status_code = 401
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            response=mock_response
        )
        mock_post.return_value = mock_response

        ds = oss_index.SonatypeGuideDataSource()
        with self.assertLogs("vulntotal.datasources.oss_index", level="ERROR") as cm:
            assert ds.fetch_json_response(["pkg:npm/foo@1.0"]) is None
            assert any("Invalid credentials" in msg for msg in cm.output)

    @mock.patch.dict(os.environ, {}, clear=True)
    @mock.patch("requests.post")
    def test_fetch_json_response_http_errors(self, mock_post):
        for status_code in (401, 429, 500):
            mock_response = mock.MagicMock()
            mock_response.status_code = status_code
            error = requests.exceptions.HTTPError(response=mock_response)
            mock_response.raise_for_status.side_effect = error
            mock_post.return_value = mock_response
            mock_post.side_effect = None

            ds = oss_index.SonatypeGuideDataSource()
            assert ds.fetch_json_response(["pkg:npm/foo@1.0"]) is None

    def test_datasource_advisory_unsupported_purl(self):
        ds = oss_index.SonatypeGuideDataSource()
        unsupported = PackageURL.from_string("pkg:unsupported/foo@1.0")
        assert ds.datasource_advisory(unsupported) is None
