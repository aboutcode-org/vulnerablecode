#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from pathlib import Path

from commoncode import testcase

from vulnerabilities.pipelines.v2_importers import zyxel_importer


class TestZyxelImporterPipeline(testcase.FileBasedTesting):
    test_data_dir = Path(__file__).parent.parent.parent / "test_data" / "zyxel_v2"

    def test_parse_listing_for_advisory_urls(self):
        listing_file = self.get_test_loc("security_advisories_listing.html")
        raw_html = Path(listing_file).read_text()

        urls = zyxel_importer.parse_listing_for_advisory_urls(
            raw_html=raw_html,
            base_url="https://www.zyxel.com/global/en/support/security-advisories",
        )

        assert urls == [
            "https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-cve-2024-7261",
            "https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-cve-2024-7263",
        ]

    def test_parse_zyxel_advisory_page_extracts_cves_and_id(self):
        advisory_file = self.get_test_loc("zyxel_security_advisory_for_foo.html")
        raw_html = Path(advisory_file).read_text()

        result = zyxel_importer.parse_zyxel_advisory_page(
            raw_html=raw_html,
            advisory_url="https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-foo",
        )

        assert result.advisory_id == "zyxel-zyxel-security-advisory-for-foo"
        assert result.summary == "ZyXEL Security Advisory for Foo"
        assert result.aliases == ["CVE-2025-12345", "CVE-2025-67890"]
        assert result.date_published.isoformat() == "2025-03-10T00:00:00+00:00"

        reference_urls = [ref.url for ref in result.references]
        assert "https://nvd.nist.gov/vuln/detail/CVE-2025-12345" in reference_urls
        assert "https://nvd.nist.gov/vuln/detail/CVE-2025-67890" in reference_urls

    def test_get_advisory_id_hash_fallback_when_slug_missing(self):
        advisory_id = zyxel_importer.get_advisory_id(
            advisory_url="https://www.zyxel.com/global/en/support/security-advisories/",
            aliases=["CVE-2025-12345"],
            summary="Example advisory",
            date_published=None,
        )

        assert advisory_id.startswith("zyxel-")
        assert advisory_id != "zyxel-security-advisories"
