#
# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
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
from unittest.mock import patch
from unittest import TestCase

from packageurl import PackageURL

from vulnerabilities.importers.safety_db import PypiVersionAPI
from vulnerabilities.importers.safety_db import categorize_versions
from vulnerabilities.importers.safety_db import SafetyDbDataSource
from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import Reference
from vulnerabilities.helpers import AffectedPackage

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data", "safety_db")

MOCK_VERSION_API = PypiVersionAPI(
    cache={
        "ampache": {"2.0", "5.2.1"},
        "django": {"1.8", "1.4.19", "1.4.22", "1.5.1", "1.6.9", "1.8.14"},
        "zulip": {"2.0", "2.1.1", "2.1.2", "2.1.3"},
    }
)


class SafetyDbtTest(TestCase):
    def test_import(self):
        data_src = SafetyDbDataSource(1, config={"url": "https://gmail.com/", "etags": ""})
        with open(os.path.join(TEST_DATA, "insecure_full.json")) as f:
            raw_data = json.load(f)
        data_src._api_response = raw_data
        data_src._versions = MOCK_VERSION_API

        expected_data = [
            Advisory(
                summary="The utils.http.is_safe_url function in Django before 1.4.20, 1.5.x, 1.6.x before 1.6.11, 1.7.x before 1.7.7, and 1.8.x before 1.8c1 does not properly validate URLs, which allows remote attackers to conduct cross-site scripting (XSS) attacks via a control character in a URL, as demonstrated by a \\x08javascript: URL.",
                vulnerability_id="CVE-2015-2317",
                affected_packages=[
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="pypi",
                            namespace=None,
                            name="django",
                            version="1.4.19",
                            qualifiers={},
                            subpath=None,
                        ),
                        patched_package=PackageURL(
                            type="pypi",
                            namespace=None,
                            name="django",
                            version="1.4.22",
                            qualifiers={},
                            subpath=None,
                        ),
                    ),
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="pypi",
                            namespace=None,
                            name="django",
                            version="1.5.1",
                            qualifiers={},
                            subpath=None,
                        ),
                        patched_package=PackageURL(
                            type="pypi",
                            namespace=None,
                            name="django",
                            version="1.8.14",
                            qualifiers={},
                            subpath=None,
                        ),
                    ),
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="pypi",
                            namespace=None,
                            name="django",
                            version="1.6.9",
                            qualifiers={},
                            subpath=None,
                        ),
                        patched_package=PackageURL(
                            type="pypi",
                            namespace=None,
                            name="django",
                            version="1.8.14",
                            qualifiers={},
                            subpath=None,
                        ),
                    ),
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="pypi",
                            namespace=None,
                            name="django",
                            version="1.8",
                            qualifiers={},
                            subpath=None,
                        ),
                        patched_package=PackageURL(
                            type="pypi",
                            namespace=None,
                            name="django",
                            version="1.8.14",
                            qualifiers={},
                            subpath=None,
                        ),
                    ),
                ],
                references=[Reference(reference_id="pyup.io-25713", url="", severities=[])],
            ),
            Advisory(
                summary="Cross-site scripting (XSS) vulnerability in the dismissChangeRelatedObjectPopup function in contrib/admin/static/admin/js/admin/RelatedObjectLookups.js in Django before 1.8.14, 1.9.x before 1.9.8, and 1.10.x before 1.10rc1 allows remote attackers to inject arbitrary web script or HTML via vectors involving unsafe usage of Element.innerHTML.",
                vulnerability_id="CVE-2016-6186",
                affected_packages=[
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="pypi",
                            namespace=None,
                            name="django",
                            version="1.8.14",
                            qualifiers={},
                            subpath=None,
                        ),
                        patched_package=None,
                    )
                ],
                references=[Reference(reference_id="pyup.io-25721", url="", severities=[])],
            ),
        ]

        found_data = [adv for adv in data_src.updated_advisories()]

        assert expected_data == found_data


def test_categorize_versions():
    all_versions = {"1.8", "1.4.19", "1.4.22", "1.5.1", "1.6.9", "1.8.14"}
    version_specs = [">=1.8,<1.8.3", "<1.4.20", ">=1.5,<1.6", ">=1.6,<1.6.11", ">=1.7,<1.7.7"]

    impacted_purls, resolved_purls = categorize_versions("django", all_versions, version_specs)

    assert len(impacted_purls) == 4
    assert len(resolved_purls) == 2

    impacted_versions = {p.version for p in impacted_purls}
    resolved_versions = {p.version for p in resolved_purls}

    assert impacted_versions == {"1.8", "1.4.19", "1.5.1", "1.6.9"}
    assert resolved_versions == {"1.4.22", "1.8.14"}
