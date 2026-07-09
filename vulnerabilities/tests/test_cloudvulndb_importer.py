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

import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vulnerablecode.settings")
os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("ALTCHA_HMAC_KEY", "0123456789abcdef0123456789abcdef")
django.setup()

from vulnerabilities.pipelines.v2_importers.cloudvulndb_importer import advisory_slug_from_link
from vulnerabilities.pipelines.v2_importers.cloudvulndb_importer import get_advisory_id
from vulnerabilities.pipelines.v2_importers.cloudvulndb_importer import parse_advisory_data
from vulnerabilities.pipelines.v2_importers.cloudvulndb_importer import parse_structured_advisory_data
from vulnerabilities.pipelines.v2_importers.cloudvulndb_importer import parse_rss_feed
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/cloudvulndb")


def _load_rss(filename="cloudvulndb_rss_mock.xml"):
    with open(os.path.join(TEST_DATA, filename), encoding="utf-8") as f:
        return f.read()


class TestCloudVulnDBImporter(TestCase):
    def test_parse_rss_feed_returns_correct_item_count(self):
        items = parse_rss_feed(_load_rss())
        self.assertEqual(len(items), 2)

    def test_parse_advisory_with_guid_and_cves(self):
        items = parse_rss_feed(_load_rss())
        result = parse_advisory_data(items[0])
        self.assertIsNotNone(result)
        result_dict = result.to_dict()
        expected_file = os.path.join(TEST_DATA, "expected_cloudvulndb_advisory_output1.json")
        util_tests.check_results_against_json(result_dict, expected_file)

    def test_parse_advisory_without_guid_falls_back_to_link_slug(self):
        items = parse_rss_feed(_load_rss())
        result = parse_advisory_data(items[1])
        self.assertIsNotNone(result)
        self.assertEqual(result.advisory_id, "azure-imds-ssrf")
        self.assertEqual(result.aliases, [])

    def test_get_advisory_id_hash_fallback(self):
        advisory_id = get_advisory_id(
            guid="",
            link="",
            title="Example advisory title",
            pub_date="Mon, 08 Jul 2024 00:00:00 GMT",
        )
        self.assertTrue(advisory_id.startswith("cloudvulndb-"))
        self.assertEqual(len(advisory_id), len("cloudvulndb-") + 16)

    def test_parse_rss_feed_invalid_xml_returns_empty(self):
        result = parse_rss_feed("not valid xml <>>>")
        self.assertEqual(result, [])

    def test_advisory_slug_from_link(self):
        slug = advisory_slug_from_link("https://www.cloudvulndb.org/vulnerabilities/aws-example/")
        self.assertEqual(slug, "aws-example")

    def test_parse_structured_advisory_without_purl(self):
        structured = {
            "id": "CLOUD-2026-0001",
            "title": "Azure Entra ID token validation issue",
            "description": "Impacts Azure Entra ID service. CVE-2026-12345",
            "references": [{"url": "https://example.com/cloud/advisory-1"}],
        }

        advisory = parse_structured_advisory_data(
            item=structured,
            advisory_url="https://github.com/wiz-sec/open-cvdb/blob/main/advisories/sample.yaml",
        )

        self.assertIsNotNone(advisory)
        self.assertEqual(advisory.advisory_id, "CLOUD-2026-0001")
        self.assertIn("CVE-2026-12345", advisory.aliases)
        self.assertEqual(advisory.affected_packages, [])
        self.assertGreaterEqual(len(advisory.references), 1)
