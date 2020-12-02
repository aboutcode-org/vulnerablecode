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
#  VulnerableCode is a free software from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import os
import json
from dateutil import parser as dateparser

from unittest import TestCase
from vulnerabilities.importers import NVDDataSource
from vulnerabilities.data_source import Reference
from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import VulnerabilitySeverity

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/nvd/nvd_test.json")


class TestNVDDataSource(TestCase):
    @classmethod
    def setUpClass(cls):
        data_source_cfg = {"etags": {}}
        cls.data_src = NVDDataSource(1, config=data_source_cfg)
        with open(TEST_DATA) as f:
            cls.nvd_data = json.load(f)

    def test_extract_cpes(self):
        expected_cpes = {
            "cpe:2.3:a:csilvers:gperftools:0.1:*:*:*:*:*:*:*",
            "cpe:2.3:a:csilvers:gperftools:0.2:*:*:*:*:*:*:*",
            "cpe:2.3:h:google:chrome:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:csilvers:gperftools:*:*:*:*:*:*:*:*",
        }

        found_cpes = set()
        for cve_item in self.nvd_data["CVE_Items"]:
            found_cpes.update(NVDDataSource.extract_cpes(cve_item))

        assert expected_cpes == found_cpes

    def test_related_to_hardware(self):
        # Only CVE-2005-4900 is supposed to be a hardware related
        # vulnerability.
        for cve_item in self.nvd_data["CVE_Items"]:
            expected_result = "CVE-2005-4900" == cve_item["cve"]["CVE_data_meta"]["ID"]
            assert self.data_src.related_to_hardware(cve_item) == expected_result

    def test_extract_summary_with_single_summary(self):
        expected_summary = (
            "Multiple integer overflows in TCMalloc (tcmalloc.cc) in gperftools "
            "before 0.4 make it easier for context-dependent attackers to perform memory-related "
            "attacks such as buffer overflows via a large size value, which causes less memory to "
            "be allocated than expected."
        )
        cve_item = self.nvd_data["CVE_Items"][0]
        assert len(cve_item["cve"]["description"]["description_data"]) == 1
        found_summary = NVDDataSource.extract_summary(cve_item)
        assert found_summary == expected_summary

    def test_extract_summary_with_multiple_summary(self):
        expected_summary = (
            "SHA-1 is not collision resistant, which makes it easier for context-dependent "
            "attackers to conduct spoofing attacks, as demonstrated by attacks on the use of SHA-1"
            " in TLS 1.2.  NOTE: this CVE exists to provide a common identifier for referencing "
            "this SHA-1 issue; the existence of an identifier is not, by itself, a technology "
            "recommendation."
        )
        cve_item = self.nvd_data["CVE_Items"][1]
        assert len(cve_item["cve"]["description"]["description_data"]) > 1
        found_summary = NVDDataSource.extract_summary(cve_item)
        assert found_summary == expected_summary

    def test_is_outdated(self):
        cve_item = self.nvd_data["CVE_Items"][0]
        assert self.data_src.is_outdated(cve_item) is False

        self.data_src.config.cutoff_date = dateparser.parse("2019-08-05 13:14:17.733232+05:30")
        assert self.data_src.is_outdated(cve_item)
        self.data_src.config.cutoff_date = None  # cleanup

        assert self.data_src.is_outdated(cve_item) is False

        self.data_src.config.last_run_date = dateparser.parse("2019-08-05 13:14:17.733232+05:30")
        assert self.data_src.is_outdated(cve_item)

        self.data_src.config.last_run_date = dateparser.parse("2000-08-05 13:14:17.733232+05:30")
        assert self.data_src.is_outdated(cve_item) is False
        self.data_src.config.last_run_date = None  # cleanup

    def test_extract_reference_urls(self):
        cve_item = self.nvd_data["CVE_Items"][1]
        expected_urls = {
            "http://ia.cr/2007/474",
            "http://shattered.io/",
            "http://www.cwi.nl/news/2017/cwi-and-google-announce-first-collision-industry-security-standard-sha-1",  # nopep8
            "http://www.securityfocus.com/bid/12577",
            "https://arstechnica.com/security/2017/02/at-deaths-door-for-years-widely-used-sha1-function-is-now-dead/",  # nopep8
            "https://security.googleblog.com/2015/12/an-update-on-sha-1-certificates-in.html",
            "https://security.googleblog.com/2017/02/announcing-first-sha1-collision.html",
            "https://sites.google.com/site/itstheshappening",
            "https://www.schneier.com/blog/archives/2005/02/sha1_broken.html",
            "https://www.schneier.com/blog/archives/2005/08/new_cryptanalyt.html",
        }

        found_urls = self.data_src.extract_reference_urls(cve_item)

        assert found_urls == expected_urls

    def test_to_advisories(self):

        expected_advisories = [
            Advisory(
                summary=(
                    "Multiple integer overflows in TCMalloc (tcmalloc.cc) in gperftools "
                    "before 0.4 make it easier for context-dependent attackers to perform memory-related "  # nopep8
                    "attacks such as buffer overflows via a large size value, which causes less memory to "  # nopep8
                    "be allocated than expected."
                ),
                impacted_package_urls=[],
                resolved_package_urls=[],
                vuln_references=sorted(
                    [
                        Reference(
                            url="http://code.google.com/p/gperftools/source/browse/tags/perftools-0.4/ChangeLog",  # nopep8
                        ),
                        Reference(
                            url="http://kqueue.org/blog/2012/03/05/memory-allocator-security-revisited/",  # nopep8
                        ),
                        Reference(
                            url="https://nvd.nist.gov/vuln/detail/CVE-2005-4895",  # nopep8
                            scores=[
                                VulnerabilitySeverity(severity_type="cvssV2", severity_value="5.0")
                            ],
                            reference_id="CVE-2005-4895",
                        ),
                    ],
                    key=lambda x: x.url,
                ),
                cve_id="CVE-2005-4895",
            )
        ]
        assert len(self.nvd_data["CVE_Items"]) == 2

        found_advisories = list(self.data_src.to_advisories(self.nvd_data))
        # Only 1 advisory because other advisory is hardware related
        assert len(found_advisories) == 1
        found_advisories[0].vuln_references = sorted(found_advisories[0].vuln_references, key=lambda x: x.url)  # nopep8
        assert expected_advisories == found_advisories
