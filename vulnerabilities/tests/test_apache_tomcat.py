#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import os
from unittest.mock import patch

from univers.version_constraint import VersionConstraint
from univers.version_range import ApacheVersionRange
from univers.version_range import MavenVersionRange
from univers.versions import MavenVersion
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importers.apache_tomcat import ApacheTomcatImporter
from vulnerabilities.importers.apache_tomcat import extract_tomcat_advisory_data_from_page
from vulnerabilities.importers.apache_tomcat import to_version_ranges_apache
from vulnerabilities.importers.apache_tomcat import to_version_ranges_maven
from vulnerabilities.improvers.default import DefaultImprover
from vulnerabilities.improvers.valid_versions import ApacheTomcatImprover
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/apache_tomcat")


def test_method_extract_advisories_from_page():
    with open(os.path.join(TEST_DATA, "apache_tomcat-selected-advisories.html")) as f:
        raw_data = f.read()
    extracted_advisories = ApacheTomcatImporter().extract_advisories_from_page(raw_data)

    results = [adv.to_dict() for adv in extracted_advisories]

    expected_file = os.path.join(
        TEST_DATA, f"parse-apache_tomcat-selected-advisories-expected.json"
    )
    util_tests.check_results_against_json(results, expected_file)


@patch("vulnerabilities.improvers.valid_versions.ApacheTomcatImprover.get_package_versions")
def test_apache_tomcat_improver(mock_response):
    advisory_file = os.path.join(
        TEST_DATA, f"parse-apache_tomcat-selected-advisories-expected.json"
    )
    with open(advisory_file) as exp:
        advisories = [AdvisoryData.from_dict(adv) for adv in (json.load(exp))]
    mock_response.return_value = [
        "1.1.0",
        "1.1.1",
        "1.1.2",
        "1.1.3",
        "1.1.4",
        "1.1.5",
        "1.1.6",
        "1.1.7",
        "1.1.8",
    ]
    improvers = [ApacheTomcatImprover(), DefaultImprover()]
    result = []
    for improver in improvers:
        for advisory in advisories:
            inference = [data.to_dict() for data in improver.get_inferences(advisory)]
            result.extend(inference)
    expected_file = os.path.join(TEST_DATA, f"apache-tomcat-improver-expected.json")
    util_tests.check_results_against_json(result, expected_file)


def test_extract_advisories_from_page():
    page = """
    <h3 id="Fixed_in_Apache_Tomcat_10.0.5"><span class="pull-right">6 April 2021</span> Fixed in Apache Tomcat 10.0.5</h3><div class="text">

        <p><strong>Important: Denial of Service</strong>
        <a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-30639" rel="nofollow">CVE-2021-30639</a></p>

        <p>An error introduced as part of a change to improve error handling.</p>
        <o>Applications that do not use non-blocking I/O are not exposed to this vulnerability.</o>

        <p>This was fixed with commit
        <a href="https://github.com/apache/tomcat/commit/b59099e4ca501a039510334ebe1024971cd6f959">b59099e4</a>.</p>

        <p>This issue was reported publicly as <a href="https://bz.apache.org/bugzilla/show_bug.cgi?id=65203">65203</a>.</p>

        <p>Affects: 10.0.3 to 10.0.4</p>

    </div>
    """

    expected = [
        {
            "advisory_groups": [
                [
                    "<p><strong>Important: Denial of Service</strong>\n"
                    "<a "
                    'href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-30639" '
                    'rel="nofollow">CVE-2021-30639</a></p>',
                    "<p>An error introduced as part of a change to improve " "error handling.</p>",
                    "<o>Applications that do not use non-blocking I/O are "
                    "not exposed to this vulnerability.</o>",
                    "<p>This was fixed with commit\n"
                    "        <a "
                    'href="https://github.com/apache/tomcat/commit/b59099e4ca501a039510334ebe1024971cd6f959">b59099e4</a>.</p>',
                    "<p>This issue was reported publicly as <a "
                    'href="https://bz.apache.org/bugzilla/show_bug.cgi?id=65203">65203</a>.</p>',
                    "<p>Affects: 10.0.3 to 10.0.4</p>",
                ]
            ],
            "fixed_versions": ["10.0.5"],
        },
    ]
    results = extract_tomcat_advisory_data_from_page(page)
    results = [d.to_dict() for d in results]
    assert results == expected


def test_extract_advisories_from_page_with_multiple_groups():
    page = """
<h3 id="Fixed_in_Apache_Tomcat_10.0.2"><span class="pull-right">2 February 2021</span> Fixed in Apache Tomcat 10.0.2</h3><div class="text">

    <p><i>Note: The issues below were fixed in Apache Tomcat 10.0.1 but the
       release vote for the 10.0.1 release candidate did not pass. Therefore,
       although users must download 10.0.2 to obtain a version that includes a
       fix for these issues, version 10.0.1 is not included in the list of
       affected versions.</i></p>

    <p><strong>Low: Fix for <a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9484" rel="nofollow">CVE-2020-9484</a> was incomplete</strong>
       <a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-25329" rel="nofollow">CVE-2021-25329</a></p>

    <p>The fix for <a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9484" rel="nofollow">CVE-2020-9484</a> was incomplete. When using a
    highly unlikely configuration edge case, the Tomcat instance was still
    vulnerable to <a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9484" rel="nofollow">CVE-2020-9484</a>. Note that both the previously
    published prerequisites for <a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9484" rel="nofollow">CVE-2020-9484</a> and the previously
    published non-upgrade mitigations for <a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9484" rel="nofollow">CVE-2020-9484</a> also apply to
    this issue.</p>

    <p>This was fixed with commit
       <a href="https://github.com/apache/tomcat/commit/6d66e99ef85da93e4d2c2a536ca51aa3418bfaf4">6d66e99e</a>.</p>

    <p>This issue was reported to the Apache Tomcat Security team by Trung Pham
       of Viettel Cyber Security on 12 January 2021. The issue was made public
       on 1 March 2021.</p>

    <p>Affects: 10.0.0-M1 to 10.0.0</p>

    <p><strong>Important: Request mix-up with h2c</strong>
       <a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-25122" rel="nofollow">CVE-2021-25122</a></p>

    <p>When responding to new h2c connection requests, Apache Tomcat could
    duplicate request headers and a limited amount of request body from one
    request to another meaning user A and user B could both see the results of
    user A's request.</p>

    <p>This was fixed with commit
       <a href="https://github.com/apache/tomcat/commit/dd757c0a893e2e35f8bc1385d6967221ae8b9b9b">dd757c0a</a>.</p>

    <p>This issue was identified by the Apache Tomcat Security team on 11
       January 2021. The issue was made public on 1 March 2021.</p>

    <p>Affects: 10.0.0-M1 to 10.0.0</p>

  </div><h3 id="Fixed_in_Apache_Tomcat_10.0.0-M10"><span class="pull-right">17 November 2020</span> Fixed in Apache Tomcat 10.0.0-M10</h3><div class="text">

    <p><strong>Important: Information disclosure</strong>
       <a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24122" rel="nofollow">CVE-2021-24122</a></p>

    <p>When serving resources from a network location using the NTFS file system
       it was possible to bypass security constraints and/or view the source
       code for JSPs in some configurations. The root cause was the unexpected
       behaviour of the JRE API <code>File.getCanonicalPath()</code> which in
       turn was caused by the inconsistent behaviour of the Windows API
       (<code>FindFirstFileW</code>) in some circumstances.
    </p>

    <p>This was fixed with commit
       <a href="https://github.com/apache/tomcat/commit/7f004ac4531c45f9a2a2d1470561fe135cf27bc2">7f004ac4</a>.</p>

    <p>This issue was reported the Apache Tomcat Security team by Ilja Brander
       on 26 October 2020. The issue was made public on 14 January 2021.</p>

    <p>Affects: 10.0.0-M1 to 10.0.0-M9</p>

    <p><strong>Moderate: HTTP/2 request header mix-up</strong>
       <a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-17527" rel="nofollow">CVE-2020-17527</a></p>

    <p>While investigating issue <a href="https://bz.apache.org/bugzilla/show_bug.cgi?id=64830">64830</a> it was discovered that Apache
       Tomcat could re-use an HTTP request header value from the previous stream
       received on an HTTP/2 connection for the request associated with the
       subsequent stream. While this would most likely lead to an error and the
       closure of the HTTP/2 connection, it is possible that information could
       leak between requests.
    </p>

    <p>This was fixed with commit
       <a href="https://github.com/apache/tomcat/commit/8d2fe6894d6e258a6d615d7f786acca80e6020cb">8d2fe689</a>.</p>

    <p>This issue was identified by the Apache Tomcat Security team on 10
       November 2020. The issue was made public on 3 December 2020.</p>

    <p>Affects: 10.0.0-M1 to 10.0.0-M9</p>

  </div>
    """

    expected = [
        {
            "advisory_groups": [
                [
                    "<p><strong>Low: Fix for <a "
                    'href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9484" '
                    'rel="nofollow">CVE-2020-9484</a> was '
                    "incomplete</strong>\n"
                    "<a "
                    'href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-25329" '
                    'rel="nofollow">CVE-2021-25329</a></p>',
                    "<p>The fix for <a "
                    'href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9484" '
                    'rel="nofollow">CVE-2020-9484</a> was incomplete. When '
                    "using a\n"
                    "    highly unlikely configuration edge case, the "
                    "Tomcat instance was still\n"
                    "    vulnerable to <a "
                    'href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9484" '
                    'rel="nofollow">CVE-2020-9484</a>. Note that both the '
                    "previously\n"
                    "    published prerequisites for <a "
                    'href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9484" '
                    'rel="nofollow">CVE-2020-9484</a> and the previously\n'
                    "    published non-upgrade mitigations for <a "
                    'href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9484" '
                    'rel="nofollow">CVE-2020-9484</a> also apply to\n'
                    "    this issue.</p>",
                    "<p>This was fixed with commit\n"
                    "       <a "
                    'href="https://github.com/apache/tomcat/commit/6d66e99ef85da93e4d2c2a536ca51aa3418bfaf4">6d66e99e</a>.</p>',
                    "<p>This issue was reported to the Apache Tomcat "
                    "Security team by Trung Pham\n"
                    "       of Viettel Cyber Security on 12 January 2021. "
                    "The issue was made public\n"
                    "       on 1 March 2021.</p>",
                    "<p>Affects: 10.0.0-M1 to 10.0.0</p>",
                ],
                [
                    "<p><strong>Important: Request mix-up with "
                    "h2c</strong>\n"
                    "<a "
                    'href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-25122" '
                    'rel="nofollow">CVE-2021-25122</a></p>',
                    "<p>When responding to new h2c connection requests, "
                    "Apache Tomcat could\n"
                    "    duplicate request headers and a limited amount of "
                    "request body from one\n"
                    "    request to another meaning user A and user B could "
                    "both see the results of\n"
                    "    user A's request.</p>",
                    "<p>This was fixed with commit\n"
                    "       <a "
                    'href="https://github.com/apache/tomcat/commit/dd757c0a893e2e35f8bc1385d6967221ae8b9b9b">dd757c0a</a>.</p>',
                    "<p>This issue was identified by the Apache Tomcat "
                    "Security team on 11\n"
                    "       January 2021. The issue was made public on 1 "
                    "March 2021.</p>",
                    "<p>Affects: 10.0.0-M1 to 10.0.0</p>",
                ],
            ],
            "fixed_versions": ["10.0.2"],
        },
        {
            "advisory_groups": [
                [
                    "<p><strong>Important: Information disclosure</strong>\n"
                    "<a "
                    'href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24122" '
                    'rel="nofollow">CVE-2021-24122</a></p>',
                    "<p>When serving resources from a network location "
                    "using the NTFS file system\n"
                    "       it was possible to bypass security constraints "
                    "and/or view the source\n"
                    "       code for JSPs in some configurations. The root "
                    "cause was the unexpected\n"
                    "       behaviour of the JRE API "
                    "<code>File.getCanonicalPath()</code> which in\n"
                    "       turn was caused by the inconsistent behaviour "
                    "of the Windows API\n"
                    "       (<code>FindFirstFileW</code>) in some "
                    "circumstances.\n"
                    "    </p>",
                    "<p>This was fixed with commit\n"
                    "       <a "
                    'href="https://github.com/apache/tomcat/commit/7f004ac4531c45f9a2a2d1470561fe135cf27bc2">7f004ac4</a>.</p>',
                    "<p>This issue was reported the Apache Tomcat Security "
                    "team by Ilja Brander\n"
                    "       on 26 October 2020. The issue was made public "
                    "on 14 January 2021.</p>",
                    "<p>Affects: 10.0.0-M1 to 10.0.0-M9</p>",
                ],
                [
                    "<p><strong>Moderate: HTTP/2 request header "
                    "mix-up</strong>\n"
                    "<a "
                    'href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-17527" '
                    'rel="nofollow">CVE-2020-17527</a></p>',
                    "<p>While investigating issue <a "
                    'href="https://bz.apache.org/bugzilla/show_bug.cgi?id=64830">64830</a> '
                    "it was discovered that Apache\n"
                    "       Tomcat could re-use an HTTP request header "
                    "value from the previous stream\n"
                    "       received on an HTTP/2 connection for the "
                    "request associated with the\n"
                    "       subsequent stream. While this would most likely "
                    "lead to an error and the\n"
                    "       closure of the HTTP/2 connection, it is "
                    "possible that information could\n"
                    "       leak between requests.\n"
                    "    </p>",
                    "<p>This was fixed with commit\n"
                    "       <a "
                    'href="https://github.com/apache/tomcat/commit/8d2fe6894d6e258a6d615d7f786acca80e6020cb">8d2fe689</a>.</p>',
                    "<p>This issue was identified by the Apache Tomcat "
                    "Security team on 10\n"
                    "       November 2020. The issue was made public on 3 "
                    "December 2020.</p>",
                    "<p>Affects: 10.0.0-M1 to 10.0.0-M9</p>",
                ],
            ],
            "fixed_versions": ["10.0.0-M10"],
        },
    ]

    results = extract_tomcat_advisory_data_from_page(page)
    results = [d.to_dict() for d in results]
    assert results == expected


def test_fetch_links():
    retrieved_links = ApacheTomcatImporter().fetch_advisory_links(
        "https://tomcat.apache.org/security"
    )

    generator_result = []
    for link in retrieved_links:
        generator_result.append(link)

    assert generator_result == [
        "https://tomcat.apache.org/security-11.html",
        "https://tomcat.apache.org/security-10.html",
        "https://tomcat.apache.org/security-9.html",
        "https://tomcat.apache.org/security-8.html",
        "https://tomcat.apache.org/security-7.html",
        "https://tomcat.apache.org/security-6.html",
        "https://tomcat.apache.org/security-5.html",
        "https://tomcat.apache.org/security-4.html",
        "https://tomcat.apache.org/security-3.html",
    ]


def test_to_version_ranges():
    versions_data = [
        "1.0.0-2.0.0",
        "3.2.2-3.2.3",
        "3.3a-3.3.1",
        "9.0.0.M1 to 9.0.0.M9",
        "10.1.0-M1 to 10.1.0-M16",
    ]
    fixed_versions = ["3.0.0", "3.3.1a"]

    expected_versions_data_maven = "vers:maven/>=1.0.0|<=2.0.0|!=3.0.0|>=3.2.2|<=3.2.3|>=3.3a|<=3.3.1|!=3.3.1a|>=9.0.0.M1|<=9.0.0.M9|>=10.1.0-M1|<=10.1.0-M16"

    expected_MavenVersionRange_versions_data = MavenVersionRange(
        constraints=(
            VersionConstraint(comparator=">=", version=MavenVersion(string="1.0.0")),
            VersionConstraint(comparator="<=", version=MavenVersion(string="2.0.0")),
            VersionConstraint(comparator="!=", version=MavenVersion(string="3.0.0")),
            VersionConstraint(comparator=">=", version=MavenVersion(string="3.2.2")),
            VersionConstraint(comparator="<=", version=MavenVersion(string="3.2.3")),
            VersionConstraint(comparator=">=", version=MavenVersion(string="3.3a")),
            VersionConstraint(comparator="<=", version=MavenVersion(string="3.3.1")),
            VersionConstraint(comparator="!=", version=MavenVersion(string="3.3.1a")),
            VersionConstraint(comparator=">=", version=MavenVersion(string="9.0.0.M1")),
            VersionConstraint(comparator="<=", version=MavenVersion(string="9.0.0.M9")),
            VersionConstraint(comparator=">=", version=MavenVersion(string="10.1.0-M1")),
            VersionConstraint(comparator="<=", version=MavenVersion(string="10.1.0-M16")),
        )
    )

    converted_versions_data_maven = to_version_ranges_maven(versions_data, fixed_versions)

    assert expected_MavenVersionRange_versions_data == converted_versions_data_maven
    assert (
        MavenVersionRange.from_string(expected_versions_data_maven) == converted_versions_data_maven
    )

    expected_versions_data_apache = "vers:apache/>=1.0.0|<=2.0.0|!=3.0.0|>=3.2.2|<=3.2.3|>=3.3a|<=3.3.1|!=3.3.1a|>=9.0.0.M1|<=9.0.0.M9|>=10.1.0-M1|<=10.1.0-M16"

    expected_ApacheVersionRange_versions_data = ApacheVersionRange(
        constraints=(
            VersionConstraint(comparator=">=", version=SemverVersion(string="1.0.0")),
            VersionConstraint(comparator="<=", version=SemverVersion(string="2.0.0")),
            VersionConstraint(comparator="!=", version=SemverVersion(string="3.0.0")),
            VersionConstraint(comparator=">=", version=SemverVersion(string="3.2.2")),
            VersionConstraint(comparator="<=", version=SemverVersion(string="3.2.3")),
            VersionConstraint(comparator=">=", version=SemverVersion(string="3.3a")),
            VersionConstraint(comparator="<=", version=SemverVersion(string="3.3.1")),
            VersionConstraint(comparator="!=", version=SemverVersion(string="3.3.1a")),
            VersionConstraint(comparator=">=", version=SemverVersion(string="9.0.0.M1")),
            VersionConstraint(comparator="<=", version=SemverVersion(string="9.0.0.M9")),
            VersionConstraint(comparator=">=", version=SemverVersion(string="10.1.0-M1")),
            VersionConstraint(comparator="<=", version=SemverVersion(string="10.1.0-M16")),
        )
    )

    converted_versions_data_apache = to_version_ranges_apache(versions_data, fixed_versions)

    assert expected_ApacheVersionRange_versions_data == converted_versions_data_apache
    assert (
        ApacheVersionRange.from_string(expected_versions_data_apache)
        == converted_versions_data_apache
    )
