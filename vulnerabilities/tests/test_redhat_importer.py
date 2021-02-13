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
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import json
import os
import unittest
from collections import OrderedDict

from packageurl import PackageURL

import vulnerabilities.importers.redhat as redhat
from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import Reference
from vulnerabilities.data_source import VulnerabilitySeverity
from vulnerabilities.severity_systems import scoring_systems, ScoringSystem

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/", "redhat.json")


def load_test_data():
    with open(TEST_DATA) as f:
        return json.load(f)


class TestRedhat(unittest.TestCase):
    def test_rpm_to_purl(self):

        assert redhat.rpm_to_purl("foobar") is None
        assert redhat.rpm_to_purl("foo-bar-devel-0:sys76") is None
        assert redhat.rpm_to_purl("kernel-0:2.6.32-754.el6") == PackageURL(
            type="rpm",
            namespace="redhat",
            name="kernel",
            version="2.6.32-754.el6",
            qualifiers=OrderedDict(),
            subpath=None,
        )

    def test_to_advisory(self):
        data = load_test_data()
        expected_data = {
            Advisory(
                summary="CVE-2016-9401 bash: popd controlled free",
                impacted_package_urls=[
                    PackageURL(
                        type="rpm",
                        namespace="redhat",
                        name="bash",
                        version="4.2.46-28.el7",
                        qualifiers={},
                        subpath=None,
                    ),
                    PackageURL(
                        type="rpm",
                        namespace="redhat",
                        name="bash",
                        version="4.1.2-48.el6",
                        qualifiers={},
                        subpath=None,
                    ),
                ],
                resolved_package_urls=[],
                vuln_references=[
                    Reference(
                        reference_id="RHSA-2017:0725",
                        url="https://access.redhat.com/errata/RHSA-2017:0725",
                        severities=[
                            VulnerabilitySeverity(
                                system=scoring_systems["rhas"],
                                value=2.2,
                            )
                        ],
                    ),
                    Reference(
                        reference_id="RHSA-2017:1931",
                        url="https://access.redhat.com/errata/RHSA-2017:1931",
                        severities=[
                            VulnerabilitySeverity(
                                system=scoring_systems["rhas"],
                                value=2.2,
                            )
                        ],
                    ),
                    Reference(
                        reference_id="",
                        url="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2016-9401.json",  # nopep8
                        severities=[
                            VulnerabilitySeverity(
                                system=scoring_systems["cvssv3"],
                                value="3.3",
                            ),
                            VulnerabilitySeverity(
                                system=scoring_systems["cvssv3_vector"],
                                value="CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L",
                            ),
                        ],
                    ),
                    Reference(
                        reference_id="1396383",
                        url="https://bugzilla.redhat.com/show_bug.cgi?id=1396383",
                        severities=[
                            VulnerabilitySeverity(
                                system=scoring_systems["rhbs"],
                                value=2.0,
                            )
                        ],
                    ),
                ],
                cve_id="CVE-2016-9401",
            )
        }

        found_data = set()
        mock_resp = unittest.mock.MagicMock()
        mock_resp.json = lambda: {
            "bugs": [{"severity": 2.0}],
            "cvrfdoc": {"aggregate_severity": 2.2},
        }
        for adv in data:
            with unittest.mock.patch(
                "vulnerabilities.importers.redhat.requests.get", return_value=mock_resp
            ):
                adv = redhat.to_advisory(adv)
                adv.vuln_references = sorted(adv.vuln_references, key=lambda x: x.url)
                found_data.add(adv)

        assert expected_data == found_data
