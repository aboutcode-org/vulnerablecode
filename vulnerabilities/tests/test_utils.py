# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an 'AS IS' BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

from packageurl import PackageURL

from vulnerabilities.utils import AffectedPackage
from vulnerabilities.utils import get_item
from vulnerabilities.utils import nearest_patched_package
from vulnerabilities.utils import split_markdown_front_matter


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
