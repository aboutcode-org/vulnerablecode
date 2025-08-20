#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from fetchcode.package_versions import PackageVersion
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import GemVersionRange
from univers.versions import RubygemsVersion

from vulnerabilities.utils import AffectedPackage
from vulnerabilities.utils import get_item
from vulnerabilities.utils import get_severity_range
from vulnerabilities.utils import nearest_patched_package
from vulnerabilities.utils import resolve_version_range
from vulnerabilities.utils import split_markdown_front_matter
from vulnerabilities.utils import ssvc_calculator


def test_nearest_patched_package():

    result = nearest_patched_package(
        vulnerable_packages=[
            PackageURL(type="npm", name="foo", version="2.0.4"),
            PackageURL(type="npm", name="foo", version="2.0.0"),
            PackageURL(type="npm", name="foo", version="2.0.1"),
            PackageURL(type="npm", name="foo", version="1.9.8"),
        ],
        resolved_packages=[
            PackageURL(type="npm", name="foo", version="2.0.2"),
            PackageURL(type="npm", name="foo", version="1.9.9"),
        ],
    )

    assert [
        AffectedPackage(
            vulnerable_package=PackageURL(
                type="npm", namespace=None, name="foo", version="1.9.8", qualifiers={}, subpath=None
            ),
            patched_package=PackageURL(
                type="npm", namespace=None, name="foo", version="1.9.9", qualifiers={}, subpath=None
            ),
        ),
        AffectedPackage(
            vulnerable_package=PackageURL(
                type="npm", namespace=None, name="foo", version="2.0.0", qualifiers={}, subpath=None
            ),
            patched_package=PackageURL(
                type="npm", namespace=None, name="foo", version="2.0.2", qualifiers={}, subpath=None
            ),
        ),
        AffectedPackage(
            vulnerable_package=PackageURL(
                type="npm", namespace=None, name="foo", version="2.0.1", qualifiers={}, subpath=None
            ),
            patched_package=PackageURL(
                type="npm", namespace=None, name="foo", version="2.0.2", qualifiers={}, subpath=None
            ),
        ),
        AffectedPackage(
            vulnerable_package=PackageURL(
                type="npm", namespace=None, name="foo", version="2.0.4", qualifiers={}, subpath=None
            ),
            patched_package=None,
        ),
    ] == result


def test_split_markdown_front_matter():
    text = """---
title: DUMMY-SECURITY-2019-001
description: Incorrect access control.
cves: [CVE-2042-1337]
---
# Markdown starts here
"""

    expected = (
        """title: DUMMY-SECURITY-2019-001
description: Incorrect access control.
cves: [CVE-2042-1337]""",
        "# Markdown starts here",
    )

    results = split_markdown_front_matter(text)
    assert results == expected


def test_get_item():
    d1 = {"a": {"b": {"c": None}}}
    assert get_item(d1, "a", "b", "c", "d") == None
    d2 = {"a": {"b": {"c": {"d": None}}}}
    assert get_item(d2, "a", "b", "c", "e") == None
    d3 = ["a", "b", "c", "d"]
    assert get_item(d3, "a", "b") == None
    d4 = {"a": {"b": {"c": {"d": []}}}}
    assert get_item(d4, "a", "b", "c", "d", "e") == None
    d5 = {"a": {"b": {"c": "d"}}}
    assert get_item(d5, "a", "b", "c", "d") == None
    assert get_item(d5, "a", "b", "c") == "d"


def test_resolve_version_range():
    assert (["1.0.0", "2.0.0"], ["10.0.0"]) == resolve_version_range(
        GemVersionRange(
            constraints=(
                VersionConstraint(comparator="<", version=RubygemsVersion(string="9.0.0")),
            )
        ),
        [
            "1.0.0",
            "2.0.0",
            "10.0.0",
        ],
        [],
    )


def test_resolve_version_range_failure(caplog):
    assert ([], []) == resolve_version_range(
        None,
        [
            PackageVersion(value="1.0.0"),
            PackageVersion(value="2.0.0"),
            PackageVersion(value="10.0.0"),
        ],
        [],
    )
    assert "affected version range is" in caplog.text


def test_resolve_version_range_without_ignorable_versions():
    assert (["1.0.0", "2.0.0"], ["10.0.0"]) == resolve_version_range(
        GemVersionRange(
            constraints=(
                VersionConstraint(comparator="<", version=RubygemsVersion(string="9.0.0")),
            )
        ),
        [
            "1.0.0",
            "2.0.0",
            "10.0.0",
        ],
    )


def test_get_severity_range():
    assert get_severity_range({""}) is None
    assert get_severity_range({}) is None


def test_ssvc_calculator1():
    assert ssvc_calculator(
        {
            "id": "CVE-2024-5396",
            "role": "CISA Coordinator",
            "options": [
                {"Exploitation": "poc"},
                {"Automatable": "no"},
                {"Technical Impact": "partial"},
            ],
            "version": "2.0.3",
            "timestamp": "2024-05-28T15:58:04.187512Z",
        }
    ) == ("SSVCv2/E:P/A:N/T:P/P:M/B:A/M:M/D:T/2024-05-28T15:58:04Z/", "Track")


def test_ssvc_calculator2():
    assert ssvc_calculator(
        {
            "id": "CVE-2024-5396",
            "role": "CISA Coordinator",
            "options": [
                {"Exploitation": "active"},
                {"Automatable": "no"},
                {"Technical Impact": "total"},
                {"Mission Prevalence": "Minimal"},
                {"Public Well-being Impact": "Material"},
                {"Mission & Well-being": "medium"},
            ],
            "version": "2.0.3",
            "timestamp": "2024-05-28T15:58:04.187512Z",
        }
    ) == ("SSVCv2/E:A/A:N/T:T/P:M/B:A/M:M/D:A/2024-05-28T15:58:04Z/", "Attend")
