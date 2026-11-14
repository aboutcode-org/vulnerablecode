#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from unittest.mock import Mock
from unittest.mock import patch

from django.test import SimpleTestCase
from packageurl import PackageURL

from vulnerabilities.pipes.fetchcode_utils import get_versions


class TestGetGolangVersions(SimpleTestCase):
    @patch("vulnerabilities.pipes.fetchcode_utils.requests.get")
    def test_uses_list_and_skips_info(self, mock_get):
        response = Mock()
        response.status_code = 200
        response.text = "v3.0.0-beta1\nv3.0.0\nv3.1.0\n"
        response.raise_for_status = Mock()
        mock_get.return_value = response

        versions = get_versions(PackageURL.from_string("pkg:golang/github.com/traefik/traefik/v3"))

        self.assertEqual(versions, {"3.0.0-beta1", "3.0.0", "3.1.0"})
        mock_get.assert_called_once()
        self.assertTrue(
            mock_get.call_args.args[0].endswith("/github.com/traefik/traefik/v3/@v/list")
        )

    @patch("vulnerabilities.pipes.fetchcode_utils.requests.get")
    def test_walks_up_module_path_on_404(self, mock_get):
        missing = Mock()
        missing.status_code = 404
        found = Mock()
        found.status_code = 200
        found.text = "v1.2.3\n"
        found.raise_for_status = Mock()
        mock_get.side_effect = [missing, found]

        versions = get_versions(
            PackageURL.from_string("pkg:golang/github.com/example/mod/internal/pkg")
        )

        self.assertEqual(versions, {"1.2.3"})
        urls = [call.args[0] for call in mock_get.call_args_list]
        self.assertTrue(urls[0].endswith("/github.com/example/mod/internal/pkg/@v/list"))
        self.assertTrue(urls[1].endswith("/github.com/example/mod/internal/@v/list"))

    @patch("vulnerabilities.pipes.fetchcode_utils.requests.get")
    def test_one_segment_vanity_module(self, mock_get):
        response = Mock()
        response.status_code = 200
        response.text = "v1.27.0\nv1.26.1\n"
        response.raise_for_status = Mock()
        mock_get.return_value = response

        versions = get_versions(PackageURL.from_string("pkg:golang/gitea.dev"))

        self.assertEqual(versions, {"1.27.0", "1.26.1"})
        self.assertTrue(mock_get.call_args.args[0].endswith("/gitea.dev/@v/list"))

    @patch("vulnerabilities.pipes.fetchcode_utils.requests.get")
    def test_stdlib_uses_go_releases(self, mock_get):
        response = Mock()
        response.status_code = 200
        response.json.return_value = [
            {"version": "go1.25.11"},
            {"version": "go1.26.4"},
            {"version": "go1.27.0-rc.3"},
        ]
        response.raise_for_status = Mock()
        mock_get.return_value = response

        import vulnerabilities.pipes.fetchcode_utils as fetchcode_utils

        fetchcode_utils._GO_RELEASE_VERSIONS = None
        versions = get_versions(PackageURL.from_string("pkg:golang/stdlib"))
        fetchcode_utils._GO_RELEASE_VERSIONS = None

        self.assertEqual(versions, {"1.25.11", "1.26.4", "1.27.0-rc.3"})
        self.assertTrue(mock_get.call_args.args[0].startswith("https://go.dev/dl/"))

    @patch("vulnerabilities.pipes.fetchcode_utils.requests.get")
    def test_cmd_go_uses_go_releases(self, mock_get):
        response = Mock()
        response.status_code = 200
        response.json.return_value = [{"version": "go1.24.0"}]
        response.raise_for_status = Mock()
        mock_get.return_value = response

        import vulnerabilities.pipes.fetchcode_utils as fetchcode_utils

        fetchcode_utils._GO_RELEASE_VERSIONS = None
        versions = get_versions(PackageURL.from_string("pkg:golang/cmd/go"))
        fetchcode_utils._GO_RELEASE_VERSIONS = None

        self.assertEqual(versions, {"1.24.0"})
