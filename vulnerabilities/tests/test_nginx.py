# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

from pathlib import Path

import pytest
from bs4 import BeautifulSoup
from commoncode import testcase

from vulnerabilities import models
from vulnerabilities import severity_systems
from vulnerabilities.import_runner import ImportRunner
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.importers import nginx
from vulnerabilities.tests import util_tests


class TestNginxImporter(testcase.FileBasedTesting):
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
        class MockNginxImporter(nginx.NginxImporter):
            """
            A mocked NginxImporter that loads content from a file rather than
            making a network call.
            """

            def fetch(self):
                with open(test_file) as tf:
                    return tf.read()

        test_file = self.get_test_loc("security_advisories.html")

        ImportRunner(MockNginxImporter).run()

        results = list(
            models.Advisory.objects.all().values(
                "unique_content_id",
                "aliases",
                "summary",
                "affected_packages",
                "references",
                "date_published",
                "created_by",
            )
        )

        expected_file = self.get_test_loc(
            "security_advisories-importer-expected.json", must_exist=False
        )
        util_tests.check_results_against_json(results, expected_file)
