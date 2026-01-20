#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


from unittest import TestCase

from vulnerabilities.importer import ReferenceV2
from vulnerabilities.models import AdvisoryReference
from vulnerabilities.pipes.openssl import get_commit_patch
from vulnerabilities.pipes.openssl import get_reference
from vulnerabilities.pipes.openssl import parse_affected_fixed
from vulnerabilities.tests.pipelines import TestLogger


class TestPipeOpenSSL(TestCase):
    def setUp(self):
        self.logger = TestLogger()

    def test_vulnerability_pipes_openssl_get_reference(self):
        refrence_name = "OpenSSL Advisory"
        tag = "vendor-advisory"
        refrence_url = "https://www.openssl.org/news/secadv/20221213.txt"
        result = get_reference(
            reference_name=refrence_name,
            tag=tag,
            reference_url=refrence_url,
        )
        expected = ReferenceV2(
            reference_id=refrence_name,
            reference_type=AdvisoryReference.ADVISORY,
            url=refrence_url,
        )

        self.assertEqual(result, expected)

    def test_vulnerability_pipes_openssl_get_commit_patch(self):
        url = "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=cca1cd9a3447dd067503e4a85ebd1679ee78a48e"
        result_patch = get_commit_patch(url=url, logger=self.logger.write)
        expected_vcs = "https://github.com/openssl/openssl/"
        expected_hash = "cca1cd9a3447dd067503e4a85ebd1679ee78a48e"

        self.assertEqual(result_patch.vcs_url, expected_vcs)
        self.assertEqual(result_patch.commit_hash, expected_hash)

    def test_vulnerability_pipes_openssl_get_commit_patch_unsupported(self):
        url = "https://someunsupported.url/commit/93l232slfsll3l23l2"
        get_commit_patch(url=url, logger=self.logger.write)

        self.assertIn("Unsupported commit url", self.logger.getvalue())

    def test_vulnerability_pipes_openssl_parse_affected_fixed_lessthan(self):
        affected = {
            "lessThan": "0.9.7a",
            "status": "affected",
            "version": "0.9.7",
            "versionType": "custom",
        }

        result_affected, result_fixed = parse_affected_fixed(affected)
        result_affected = [str(const) for const in result_affected]
        expected_affected = [">=0.9.7", "<0.9.7a"]
        expected_fixed = "0.9.7a"

        self.assertCountEqual(result_affected, expected_affected)
        self.assertEqual(result_fixed, expected_fixed)

    def test_vulnerability_pipes_openssl_parse_affected_fixed_lessthanorequal(self):
        affected = {
            "lessThanOrEqual": "3.0.7",
            "status": "affected",
            "version": "3.0.0",
            "versionType": "semver",
        }

        result_affected, result_fixed = parse_affected_fixed(affected)
        result_affected = [str(const) for const in result_affected]
        expected_affected = [">=3.0.0", "<=3.0.7"]
        expected_fixed = None

        self.assertCountEqual(result_affected, expected_affected)
        self.assertEqual(result_fixed, expected_fixed)
