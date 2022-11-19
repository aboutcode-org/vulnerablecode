#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
from pathlib import Path

import pytest
from commoncode import testcase
from packageurl import PackageURL

from vulnerabilities.tests import util_tests
from vulntotal.datasources import osv


class TestOSV(testcase.FileBasedTesting):
    test_data_dir = str(Path(__file__).resolve().parent / "test_data" / "osv")

    def test_generate_payload(self):
        purls = [
            "pkg:pypi/jinja2@2.4.1",
            "pkg:android/System@10",
            "pkg:debian:8/davical@1.1.3-1",
            "pkg:maven/org.apache.tomcat/tomcat@10.1.0-M8",
            "pkg:linux/Kernel@v5.4.195",
            "pkg:packagist/dolibarr/dolibarr@12.0.5",
            "pkg:crates.io/sha2@0.9.7",
            "pkg:npm/semver-regex@3.1.3",
            "pkg:golang/github.com/cloudflare/cfrpki@1.1.0",
        ]

        expected = [
            {"version": "2.4.1", "package": {"ecosystem": "PyPI", "name": "jinja2"}},
            {"version": "10", "package": {"ecosystem": "Android", "name": "System"}},
            {"version": "1.1.3-1", "package": {"name": "davical"}},
            {
                "version": "10.1.0-M8",
                "package": {"ecosystem": "Maven", "name": "org.apache.tomcat:tomcat"},
            },
            {"version": "v5.4.195", "package": {"ecosystem": "Linux", "name": "Kernel"}},
            {"version": "12.0.5", "package": {"name": "dolibarr/dolibarr"}},
            {"version": "0.9.7", "package": {"ecosystem": "crates.io", "name": "sha2"}},
            {"version": "3.1.3", "package": {"ecosystem": "npm", "name": "semver-regex"}},
            {
                "version": "1.1.0",
                "package": {"ecosystem": "Go", "name": "github.com/cloudflare/cfrpki"},
            },
        ]
        results = [osv.generate_payload(PackageURL.from_string(purl)) for purl in purls]
        assert results == expected

    def test_parse_advisory(self):
        advisory_page = self.get_test_loc("advisory.txt")
        with open(advisory_page) as f:
            advisory = json.load(f)
        results = [adv.to_dict() for adv in osv.parse_advisory(advisory)]
        expected_file = self.get_test_loc("parse_advisory_data-expected.json", must_exist=False)
        util_tests.check_results_against_json(results, expected_file)


@pytest.mark.webtest
class TestOSVLive(testcase.FileBasedTesting):
    def test_generate_payload_nuget_with_api_call(self):
        # this test makes like API calls
        purl = PackageURL.from_string("pkg:nuget/moment.js@2.18.0")
        results = osv.generate_payload(purl)
        expected = {"package": {"ecosystem": "NuGet", "name": "Moment.js"}, "version": "2.18.0"}
        assert results == expected
