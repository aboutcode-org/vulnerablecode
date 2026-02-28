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

from vulnerabilities.importers.kde import extract_summary
from vulnerabilities.importers.kde import parse_advisory

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/kde")


class TestKdeImporter(TestCase):
    def test_parse_old_format_advisory(self):
        """Test parsing old format PGP-signed advisory"""
        with open(os.path.join(TEST_DATA, "advisory-20030916-1.txt"), "r") as f:
            advisory_text = f.read()

        advisory_url = "https://kde.org/info/security/advisory-20030916-1.txt"
        result = parse_advisory(advisory_text, advisory_url)

        # Check that CVE IDs were extracted and converted from CAN format
        assert "CVE-2003-0690" in result.aliases
        assert "CVE-2003-0692" in result.aliases
        assert len(result.aliases) == 2

        # Check summary was extracted
        assert "KDM vulnerabilities" in result.summary

        # Check references include CVE URLs
        cve_urls = [ref.url for ref in result.references if "cve.mitre.org" in ref.url]
        assert len(cve_urls) == 2

    def test_parse_new_format_advisory(self):
        """Test parsing new format advisory"""
        with open(os.path.join(TEST_DATA, "advisory-20260109-1.txt"), "r") as f:
            advisory_text = f.read()

        advisory_url = "https://kde.org/info/security/advisory-20260109-1.txt"
        result = parse_advisory(advisory_text, advisory_url)

        # Check CVE IDs were extracted
        assert "CVE-2025-66002" in result.aliases
        assert "CVE-2025-66003" in result.aliases

        # Check title was extracted
        assert "Smb4K" in result.summary

    def test_extract_summary_old_format(self):
        """Test summary extraction from old format"""
        advisory_text = """-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1



KDE Security Advisory: KDM vulnerabilities
Original Release Date: 2003-09-16"""

        summary = extract_summary(advisory_text)
        assert "KDM vulnerabilities" in summary

    def test_extract_summary_new_format(self):
        """Test summary extraction from new format"""
        advisory_text = """KDE Project Security Advisory
=============================

Title:          Smb4K: Major security issues
Risk rating:    Major"""

        summary = extract_summary(advisory_text)
        assert "Smb4K" in summary
