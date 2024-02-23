#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from pathlib import Path

from commoncode import testcase
from packageurl import PackageURL

from vulnerabilities.tests import util_tests
from vulntotal.datasources import snyk


class TestSnyk(testcase.FileBasedTesting):
    test_data_dir = str(Path(__file__).resolve().parent / "test_data" / "snyk")

    def test_generate_package_advisory_url(self):
        purls = [
            "pkg:pypi/jinja2@2.4.1",
            "pkg:maven/org.apache.tomcat/tomcat@10.1.0-M8",
            "pkg:npm/semver-regex@3.1.3",
            "pkg:golang/github.com/mattermost/mattermost-server/v6/api4@0.1",
            "pkg:composer/bolt/core@0.1",
            "pkg:linux/trafficserver@5.4.1?distro=debain:11",
            "pkg:nuget/moment.js@2.18.0",
            "pkg:cocoapods/ffmpeg@0.2",
            "pkg:hex/coherence@0.2.1",
            "pkg:gem/log4j-jars@0.2",
            "pkg:unmanaged/firefox@8.9.1",
        ]
        results = [
            snyk.generate_package_advisory_url(PackageURL.from_string(purl)) for purl in purls
        ]

        expected = [
            "https://security.snyk.io/package/pip/jinja2",
            "https://security.snyk.io/package/maven/org.apache.tomcat%3Atomcat",
            "https://security.snyk.io/package/npm/semver-regex",
            "https://security.snyk.io/package/golang/github.com%2Fmattermost%2Fmattermost-server%2Fv6%2Fapi4",
            "https://security.snyk.io/package/composer/bolt%2Fcore",
            "https://security.snyk.io/package/linux/debain:11/trafficserver",
            "https://security.snyk.io/package/nuget/moment.js",
            "https://security.snyk.io/package/cocoapods/ffmpeg",
            "https://security.snyk.io/package/hex/coherence",
            "https://security.snyk.io/package/rubygems/log4j-jars",
            "https://security.snyk.io/api/listing?search=firefox&type=unmanaged",
        ]
        util_tests.check_results_against_expected(results, expected)

    def test_generate_purl(self):
        package_advisory_urls = [
            "https://security.snyk.io/package/pip/jinja2",
            "https://security.snyk.io/package/maven/org.apache.tomcat%3Atomcat",
            "https://security.snyk.io/package/npm/semver-regex",
            "https://security.snyk.io/package/npm/@urql%2Fnext",
            "https://security.snyk.io/package/npm/@lobehub%2Fchat",
            "https://security.snyk.io/package/npm/meshcentral",
            "https://security.snyk.io/package/composer/bolt%2Fcore",
            "https://security.snyk.io/package/linux/debain:11/trafficserver",
            "https://security.snyk.io/package/linux/almalinux:8/rpm-plugin-fapolicyd",
            "https://security.snyk.io/package/nuget/moment.js",
            "https://security.snyk.io/package/cocoapods/ffmpeg",
            "https://security.snyk.io/package/hex/coherence",
            "https://security.snyk.io/package/rubygems/log4j-jars",
            "https://security.snyk.io/package/golang/github.com%2Fgrafana%2Fgrafana%2Fpkg%2Fservices%2Fsqlstore%2Fmigrator",
            "https://security.snyk.io/package/golang/github.com%2Fanswerdev%2Fanswer%2Finternal%2Frepo%2Factivity",
            "https://security.snyk.io/package/golang/go.etcd.io%2Fetcd%2Fv3%2Fauth",
            "https://security.snyk.io/package/golang/gopkg.in%2Fkubernetes%2Fkubernetes.v0%2Fpkg%2Fregistry%2Fpod",
            "https://security.snyk.io/package/golang/gogs.io%2Fgogs%2Finternal%2Fdb",
            "https://security.snyk.io/package/golang/golang.org%2Fx%2Fcrypto%2Fssh",
        ]

        results = [
            PackageURL.to_string(snyk.generate_purl(package_advisory_url))
            for package_advisory_url in package_advisory_urls
        ]

        expected = [
            "pkg:pypi/jinja2",
            "pkg:maven/org.apache.tomcat/tomcat",
            "pkg:npm/semver-regex",
            "pkg:npm/%40urql/next",
            "pkg:npm/%40lobehub/chat",
            "pkg:npm/meshcentral",
            "pkg:composer/bolt/core",
            "pkg:linux/trafficserver",
            "pkg:linux/rpm-plugin-fapolicyd",
            "pkg:nuget/moment.js",
            "pkg:cocoapods/ffmpeg",
            "pkg:hex/coherence",
            "pkg:gem/log4j-jars",
            "pkg:golang/github.com/grafana/grafana/pkg/services/sqlstore/migrator",
            "pkg:golang/github.com/answerdev/answer/internal/repo/activity",
            "pkg:golang/go.etcd.io/etcd/v3/auth",
            "pkg:golang/gopkg.in/kubernetes/kubernetes.v0/pkg/registry/pod",
            "pkg:golang/gogs.io/gogs/internal/db",
            "pkg:golang/golang.org/x/crypto/ssh",
        ]

        util_tests.check_results_against_expected(results, expected)

    def test_parse_html_advisory_0(self):
        file = self.get_test_loc("html/0.html")
        with open(file) as f:
            page = f.read()
        result = snyk.parse_html_advisory(
            page, "TEST-SNYKID", ["TEST-AFFECTED"], PackageURL("generic", "namespace", "test")
        ).to_dict()
        expected_file = f"{file}-expected.json"
        util_tests.check_results_against_json(result, expected_file)

    def test_parse_html_advisory_1(self):
        file = self.get_test_loc("html/1.html")
        with open(file) as f:
            page = f.read()
        result = snyk.parse_html_advisory(
            page, "TEST-SNYKID", ["TEST-AFFECTED"], PackageURL("generic", "namespace", "test")
        ).to_dict()
        expected_file = f"{file}-expected.json"
        util_tests.check_results_against_json(result, expected_file)

    def test_parse_html_advisory_2(self):
        file = self.get_test_loc("html/2.html")
        with open(file) as f:
            page = f.read()
        result = snyk.parse_html_advisory(
            page, "TEST-SNYKID", ["TEST-AFFECTED"], PackageURL("generic", "namespace", "test")
        ).to_dict()
        expected_file = f"{file}-expected.json"
        util_tests.check_results_against_json(result, expected_file)

    def test_parse_html_advisory_3(self):
        file = self.get_test_loc("html/3.html")
        with open(file) as f:
            page = f.read()
        result = snyk.parse_html_advisory(
            page, "TEST-SNYKID", ["TEST-AFFECTED"], PackageURL("generic", "namespace", "test")
        ).to_dict()
        expected_file = f"{file}-expected.json"
        util_tests.check_results_against_json(result, expected_file)

    def test_parse_cve_advisory_html_0(self):
        file = self.get_test_loc("html/4.html")
        with open(file) as f:
            page = f.read()
        result = snyk.parse_cve_advisory_html(page)
        expected_file = f"{file}-expected.json"
        util_tests.check_results_against_json(result, expected_file)

    def test_parse_cve_advisory_html_1(self):
        file = self.get_test_loc("html/5.html")
        with open(file) as f:
            page = f.read()
        result = snyk.parse_cve_advisory_html(page)
        expected_file = f"{file}-expected.json"
        util_tests.check_results_against_json(result, expected_file)
