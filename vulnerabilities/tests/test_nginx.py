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
from unittest import mock

import pytest
from bs4 import BeautifulSoup
from commoncode import testcase
from django.db.models.query import QuerySet

from vulnerabilities import models
from vulnerabilities import severity_systems
from vulnerabilities.import_runner import ImportRunner
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.importers import nginx
from vulnerabilities.models import Advisory
from vulnerabilities.package_managers import PackageVersion
from vulnerabilities.tests import util_tests

ADVISORY_FIELDS_TO_TEST = (
    "unique_content_id",
    "aliases",
    "summary",
    "affected_packages",
    "references",
    "date_published",
)


class TestNginxImporterAndImprover(testcase.FileBasedTesting):
    test_data_dir = str(Path(__file__).resolve().parent / "test_data" / "nginx")

    def test_is_vulnerable(self):
        # Not vulnerable: 1.17.3+, 1.16.1+
        # Vulnerable: 1.9.5-1.17.2

        vcls = nginx.NginxVersionRange.version_class
        affected_version_range = nginx.NginxVersionRange.from_native("1.9.5-1.17.2")
        fixed_versions = [vcls("1.17.3"), vcls("1.16.1")]

        version = vcls("1.9.4")
        assert not nginx.is_vulnerable(version, affected_version_range, fixed_versions)

        version = vcls("1.9.5")
        assert nginx.is_vulnerable(version, affected_version_range, fixed_versions)

        version = vcls("1.9.6")
        assert nginx.is_vulnerable(version, affected_version_range, fixed_versions)

        version = vcls("1.16.0")
        assert nginx.is_vulnerable(version, affected_version_range, fixed_versions)

        version = vcls("1.16.1")
        assert not nginx.is_vulnerable(version, affected_version_range, fixed_versions)

        version = vcls("1.16.2")
        assert not nginx.is_vulnerable(version, affected_version_range, fixed_versions)

        version = vcls("1.16.99")
        assert not nginx.is_vulnerable(version, affected_version_range, fixed_versions)

        version = vcls("1.17.0")
        assert nginx.is_vulnerable(version, affected_version_range, fixed_versions)

        version = vcls("1.17.1")
        assert nginx.is_vulnerable(version, affected_version_range, fixed_versions)

        version = vcls("1.17.2")
        assert nginx.is_vulnerable(version, affected_version_range, fixed_versions)

        version = vcls("1.17.3")
        assert not nginx.is_vulnerable(version, affected_version_range, fixed_versions)

        version = vcls("1.17.4")
        assert not nginx.is_vulnerable(version, affected_version_range, fixed_versions)

        version = vcls("1.18.0")
        assert not nginx.is_vulnerable(version, affected_version_range, fixed_versions)

    def test_parse_advisory_data_from_paragraph(self):
        paragraph = (
            "<p>1-byte memory overwrite in resolver"
            "<br/>Severity: medium<br/>"
            '<a href="http://mailman.nginx.org/pipermail/nginx-announce/2021/000300.html">Advisory</a>'
            "<br/>"
            '<a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23017">CVE-2021-23017</a>'
            "<br/>Not vulnerable: 1.21.0+, 1.20.1+<br/>"
            "Vulnerable: 0.6.18-1.20.0<br/>"
            '<a href="/download/patch.2021.resolver.txt">'
            'The patch</a>  <a href="/download/patch.2021.resolver.txt.asc">pgp</a>'
            "</p>"
        )
        vuln_info = BeautifulSoup(paragraph, features="lxml").p
        expected = {
            "aliases": ["CVE-2021-23017"],
            "summary": "1-byte memory overwrite in resolver",
            "advisory_severity": VulnerabilitySeverity(
                system=severity_systems.GENERIC, value="medium"
            ),
            "not_vulnerable": "Not vulnerable: 1.21.0+, 1.20.1+",
            "vulnerable": "Vulnerable: 0.6.18-1.20.0",
            "references": [
                Reference(
                    reference_id="",
                    url="http://mailman.nginx.org/pipermail/nginx-announce/2021/000300.html",
                    severities=[
                        VulnerabilitySeverity(system=severity_systems.GENERIC, value="medium")
                    ],
                ),
                Reference(
                    reference_id="CVE-2021-23017",
                    url="https://nvd.nist.gov/vuln/detail/CVE-2021-23017",
                ),
                Reference(
                    reference_id="",
                    url="https://nginx.org/download/patch.2021.resolver.txt",
                ),
                Reference(
                    reference_id="", url="https://nginx.org/download/patch.2021.resolver.txt.asc"
                ),
            ],
        }

        result = nginx.parse_advisory_data_from_paragraph(vuln_info)
        assert result.to_dict() == expected

    def test_advisory_data_from_text(self):
        test_file = self.get_test_loc("security_advisories.html")
        with open(test_file) as tf:
            test_text = tf.read()

        expected_file = self.get_test_loc(
            "security_advisories-advisory_data-expected.json", must_exist=False
        )

        results = [na.to_dict() for na in nginx.advisory_data_from_text(test_text)]
        util_tests.check_results_against_json(results, expected_file)

    @pytest.mark.django_db(transaction=True)
    def test_NginxImporter(self):

        expected_file = self.get_test_loc(
            "security_advisories-importer-expected.json", must_exist=False
        )

        results, _cls = self.run_import()
        util_tests.check_results_against_json(results, expected_file)

        # run again as there should be no duplicates
        results, _cls = self.run_import()
        util_tests.check_results_against_json(results, expected_file)

    def run_import(self):
        """
        Return a list of imported Advisory model objects and the MockImporter
        used.
        """

        class MockImporter(nginx.NginxImporter):
            """
            A mocked NginxImporter that loads content from a file rather than
            making a network call.
            """

            def fetch(self):
                with open(test_file) as tf:
                    return tf.read()

        test_file = self.get_test_loc("security_advisories.html")

        ImportRunner(MockImporter).run()
        return list(models.Advisory.objects.all().values(*ADVISORY_FIELDS_TO_TEST)), MockImporter

    @pytest.mark.django_db(transaction=True)
    def test_NginxBasicImprover__interesting_advisories(self):
        advisories, importer_class = self.run_import()

        class MockNginxBasicImprover(nginx.NginxBasicImprover):
            @property
            def interesting_advisories(self) -> QuerySet:
                return Advisory.objects.filter(created_by=importer_class.qualified_name)

        improver = MockNginxBasicImprover()
        interesting_advisories = list(
            improver.interesting_advisories.values(*ADVISORY_FIELDS_TO_TEST)
        )
        assert interesting_advisories == advisories

    @mock.patch("vulnerabilities.utils.fetch_github_graphql_query")
    def test_NginxBasicImprover_fetch_nginx_version_from_git_tags(self, mock_fetcher):
        reponse_files = [
            "github-nginx-nginx-0.json",
            "github-nginx-nginx-1.json",
            "github-nginx-nginx-2.json",
            "github-nginx-nginx-3.json",
            "github-nginx-nginx-4.json",
            "github-nginx-nginx-5.json",
        ]
        side_effects = []
        for response_file in reponse_files:
            with open(self.get_test_loc(f"improver/{response_file}")) as f:
                side_effects.append(json.load(f))
        mock_fetcher.side_effect = side_effects

        results = [
            pv.to_dict() for pv in nginx.NginxBasicImprover().fetch_nginx_version_from_git_tags()
        ]
        expected_file = self.get_test_loc("improver/nginx-versions-expected.json", must_exist=False)
        util_tests.check_results_against_json(results, expected_file)

    @pytest.mark.django_db(transaction=True)
    def test_NginxBasicImprover__get_inferences_from_versions_end_to_end(self):

        with open(self.get_test_loc("improver/improver-advisories.json")) as vf:
            advisories_data = json.load(vf)

        with open(self.get_test_loc("improver/improver-versions.json")) as vf:
            all_versions = [PackageVersion(**vd) for vd in json.load(vf)]

        results = []
        improver = nginx.NginxBasicImprover()
        for advdata in advisories_data:
            advisory_data = AdvisoryData.from_dict(advdata)

            inferences = improver.get_inferences_from_versions(
                advisory_data=advisory_data, all_versions=all_versions
            )
            for i in inferences:
                i.vulnerability_id = "PLAIN-ID-FOR-TESTING"
                results.append(i.to_dict())

        expected_file = self.get_test_loc(
            "improver/improver-inferences-expected.json", must_exist=False
        )
        util_tests.check_results_against_json(results, expected_file)
