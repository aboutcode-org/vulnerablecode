#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os

import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vulnerablecode.settings")
os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("ALTCHA_HMAC_KEY", "0123456789abcdef0123456789abcdef")
django.setup()

from vulnerabilities.pipelines.v2_importers.enisa_nisa_importer import parse_nisa_advisory


def test_parse_nisa_advisory_extracts_minimum_cve_and_references():
    raw = {
        "title": "NISA bulletin",
        "description": "Issue in component foo. CVE-2026-11111",
        "references": [{"url": "https://example.com/nisa/bulletin"}],
    }

    advisory = parse_nisa_advisory(
        item=raw,
        advisory_url="https://github.com/enisaeu/CNW/blob/main/data/nisa.yml",
    )

    assert advisory is not None
    assert advisory.advisory_id == "CVE-2026-11111"
    assert advisory.affected_packages == []
    assert advisory.references
