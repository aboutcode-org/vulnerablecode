#
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

from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Reference
from vulnerabilities.importers.safety_db import SafetyDbImporter
from vulnerabilities.importers.safety_db import categorize_versions
from vulnerabilities.package_managers import LegacyPypiVersionAPI
from vulnerabilities.package_managers import Version
from vulnerabilities.utils import AffectedPackage

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data", "safety_db")

MOCK_VERSION_API = LegacyPypiVersionAPI(
    cache={
        "ampache": {Version("2.0"), Version("5.2.1")},
        "django": {
            Version("1.8"),
            Version("1.4.19"),
            Version("1.4.22"),
            Version("1.5.1"),
            Version("1.6.9"),
            Version("1.8.14"),
        },
        "zulip": {Version("2.0"), Version("2.1.1"), Version("2.1.2"), Version("2.1.3")},
    }
)


class SafetyDbtTest(TestCase):
    def test_import(self):
        data_src = SafetyDbImporter(1, config={"url": "https://gmail.com/", "etags": ""})
        with open(os.path.join(TEST_DATA, "insecure_full.json")) as f:
            raw_data = json.load(f)
        data_src._api_response = raw_data
        data_src._versions = MOCK_VERSION_API

        expected_data = [
            AdvisoryData(
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
            AdvisoryData(
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

        found_data = []
        # FIXME: This is messed up
        for adv_batch in data_src.updated_advisories():
            found_data.extend(adv_batch)
            # found_data = [list(adv) for adv in data_src.updated_advisories()]

        #         print(expected_data)
        #         print("\n", found_data)
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
