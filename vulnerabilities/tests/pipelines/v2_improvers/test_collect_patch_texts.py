#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import unittest
from unittest.mock import MagicMock
from unittest.mock import patch as mock_patch

from vulnerabilities.pipelines.v2_improvers.collect_patch_texts import CollectPatchTextsPipeline
from vulnerabilities.pipelines.v2_improvers.collect_patch_texts import get_raw_patch_url


class TestCollectPatchTextsPipeline(unittest.TestCase):
    def setUp(self):
        self.pipeline = CollectPatchTextsPipeline()

    def test_get_raw_patch_url(self):
        url = "https://github.com/user/repo/commit/abc1234567890"
        expected = "https://github.com/user/repo/commit/abc1234567890.patch"
        self.assertEqual(get_raw_patch_url(url), expected)

        url = "https://github.com/user/repo/pull/123"
        expected = "https://github.com/user/repo/pull/123.patch"
        self.assertEqual(get_raw_patch_url(url), expected)

        url = "https://gitlab.com/user/repo/-/commit/abc1234567890"
        expected = "https://gitlab.com/user/repo/-/commit/abc1234567890.patch"
        self.assertEqual(get_raw_patch_url(url), expected)

        url = "https://gitlab.com/user/repo/-/merge_requests/123"
        expected = "https://gitlab.com/user/repo/-/merge_requests/123.patch"
        self.assertEqual(get_raw_patch_url(url), expected)

        url = "https://example.com/fix.patch"
        self.assertEqual(get_raw_patch_url(url), url)

        url = "https://example.com/some/article"
        self.assertIsNone(get_raw_patch_url(url))

    @mock_patch("vulnerabilities.pipelines.v2_improvers.collect_patch_texts.Patch")
    @mock_patch("requests.get")
    def test_collect_and_store_patch_texts(self, mock_get, mock_patch_model):
        p1 = MagicMock(patch_url="https://github.com/u/r/commit/c1", patch_text=None)
        p2 = MagicMock(patch_url="https://github.com/u/r/pull/1", patch_text="")
        p3 = MagicMock(patch_url="https://example.com/no-patch", patch_text=None)
        p4 = MagicMock(patch_url="https://example.com/fix.patch", patch_text=None)

        mock_qs = MagicMock()
        mock_qs.count.return_value = 4
        mock_qs.iterator.return_value = [p1, p2, p3, p4]
        
        mock_patch_model.objects.filter.return_value = mock_qs

        def side_effect(url, timeout=10):
            mock_resp = MagicMock()
            mock_resp.status_code = 404
            if url == "https://github.com/u/r/commit/c1.patch":
                mock_resp.status_code = 200
                mock_resp.text = "diff --git a/file b/file\n+code"
            elif url == "https://github.com/u/r/pull/1.patch":
                mock_resp.status_code = 200
                mock_resp.text = "diff --git a/pr b/pr\n+pr_code"
            elif url == "https://example.com/fix.patch":
                mock_resp.status_code = 200
                mock_resp.text = "diff --git a/direct b/direct\n+direct_code"
            return mock_resp

        mock_get.side_effect = side_effect

        self.pipeline.collect_and_store_patch_texts()

        self.assertEqual(p1.patch_text, "diff --git a/file b/file\n+code")
        p1.save.assert_called_once()

        self.assertEqual(p2.patch_text, "diff --git a/pr b/pr\n+pr_code")
        p2.save.assert_called_once()

        p3.save.assert_not_called()

        self.assertEqual(p4.patch_text, "diff --git a/direct b/direct\n+direct_code")
        p4.save.assert_called_once()
