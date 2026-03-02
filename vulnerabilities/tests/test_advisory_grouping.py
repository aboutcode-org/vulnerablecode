#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from unittest import TestCase

import pytest
from django.test import TestCase as DjangoTestCase
from packageurl import PackageURL
from univers.version_range import VersionRange

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.pipes.advisory import insert_advisory_v2
from vulnerabilities.utils import SUMMARY_SIMILARITY_THRESHOLD
from vulnerabilities.utils import _find
from vulnerabilities.utils import _union
from vulnerabilities.utils import compute_summary_similarity
from vulnerabilities.utils import group_advisories_by_content


class TestComputeSummarySimilarity(TestCase):

    def test_empty_texts_return_zero(self):
        assert compute_summary_similarity("", "some text") == 0.0
        assert compute_summary_similarity("some text", "") == 0.0
        assert compute_summary_similarity("", "") == 0.0
        assert compute_summary_similarity(None, "text") == 0.0
        assert compute_summary_similarity("text", None) == 0.0

    def test_identical_texts_return_one(self):
        text = "A critical vulnerability in the AccessControl module."
        assert compute_summary_similarity(text, text) == 1.0

    def test_identical_after_normalization(self):
        text1 = "Security flaw in module"
        text2 = "  Security  Flaw  In  Module  "
        assert compute_summary_similarity(text1, text2) == 1.0

    def test_completely_different_texts(self):
        text1 = "Buffer overflow in network stack"
        text2 = "Unrelated cooking recipe for chocolate cake"
        similarity = compute_summary_similarity(text1, text2)
        assert similarity < SUMMARY_SIMILARITY_THRESHOLD

    def test_short_summary_contained_in_long_summary(self):
        short = (
            "The module AccessControl defines security policies for "
            "Python code used in restricted code within Zope applications."
        )
        long = (
            "The module AccessControl defines security policies for "
            "Python code used in restricted code within Zope applications. "
            "Restricted code is any code that resides in Zope's object database, "
            "such as the contents of Script (Python) objects. The policies "
            "defined in AccessControl severely restrict access to Python modules "
            "and only exempt a few that are deemed safe."
        )
        similarity = compute_summary_similarity(short, long)
        assert similarity >= SUMMARY_SIMILARITY_THRESHOLD

    def test_similar_summaries_above_threshold(self):
        text1 = "SQL injection vulnerability in login form of web application"
        text2 = "SQL injection vulnerability found in the login form of the web application"
        similarity = compute_summary_similarity(text1, text2)
        assert similarity >= SUMMARY_SIMILARITY_THRESHOLD

    def test_partially_overlapping_summaries(self):
        text1 = "Remote code execution via crafted XML payload"
        text2 = "Remote code execution through specially crafted XML input"
        similarity = compute_summary_similarity(text1, text2)
        assert similarity > 0.4

    def test_symmetry(self):
        text1 = "Cross-site scripting in admin panel"
        text2 = "XSS vulnerability found in the administration panel"
        assert compute_summary_similarity(text1, text2) == compute_summary_similarity(
            text2, text1
        )


class TestUnionFind(TestCase):

    def test_find_on_singleton(self):
        parent = [0, 1, 2]
        assert _find(parent, 0) == 0
        assert _find(parent, 2) == 2

    def test_union_merges_two_sets(self):
        parent = [0, 1, 2, 3]
        _union(parent, 0, 1)
        assert _find(parent, 0) == _find(parent, 1)

    def test_transitive_union(self):
        parent = [0, 1, 2, 3, 4]
        _union(parent, 0, 1)
        _union(parent, 2, 3)
        _union(parent, 1, 3)
        root = _find(parent, 0)
        assert _find(parent, 1) == root
        assert _find(parent, 2) == root
        assert _find(parent, 3) == root
        assert _find(parent, 4) == 4

    def test_path_compression(self):
        parent = [0, 0, 1, 2]
        root = _find(parent, 3)
        assert root == 0
        assert parent[3] == 0 or _find(parent, 3) == 0


@pytest.mark.django_db
class TestGroupAdvisoriesByContent(DjangoTestCase):

    def _create_advisory(self, advisory_id, datasource_id, summary, aliases=None, url=None):
        advisory_data = AdvisoryDataV2(
            advisory_id=advisory_id,
            aliases=aliases or [],
            summary=summary,
            affected_packages=[
                AffectedPackageV2(
                    package=PackageURL(type="pypi", name="accesscontrol"),
                    affected_version_range=VersionRange.from_string("vers:pypi/>=4.0|<4.3"),
                ),
            ],
            references=[ReferenceV2(url=url or "https://example.com")],
            url=url or f"https://example.com/{advisory_id}",
        )
        insert_advisory_v2(
            advisory=advisory_data,
            pipeline_id=datasource_id,
        )
        return AdvisoryV2.objects.get(
            datasource_id=datasource_id,
            advisory_id=advisory_id,
        )

    def test_group_by_exact_content_same_hash(self):
        adv1 = self._create_advisory(
            advisory_id="ADV-001",
            datasource_id="source_a",
            summary="Identical summary",
            url="https://source-a.example.com/ADV-001",
        )
        adv2 = self._create_advisory(
            advisory_id="ADV-001",
            datasource_id="source_b",
            summary="Identical summary",
            url="https://source-b.example.com/ADV-001",
        )
        grouped = group_advisories_by_content([adv1, adv2])
        assert len(grouped) == 1
        group = list(grouped.values())[0]
        all_advisories = {group["primary"]} | group["secondary"]
        assert adv1 in all_advisories
        assert adv2 in all_advisories

    def test_different_content_no_alias_no_similarity(self):
        adv1 = self._create_advisory(
            advisory_id="ADV-100",
            datasource_id="source_a",
            summary="Buffer overflow in network stack",
            url="https://example.com/ADV-100",
        )
        adv2 = self._create_advisory(
            advisory_id="ADV-200",
            datasource_id="source_b",
            summary="Unrelated cooking instructions for pizza dough",
            url="https://example.com/ADV-200",
        )
        grouped = group_advisories_by_content([adv1, adv2])
        assert len(grouped) == 2

    def test_group_by_shared_alias(self):
        adv1 = self._create_advisory(
            advisory_id="CVE-2021-32807",
            datasource_id="gitlab_importer_v2",
            summary="Improperly Controlled Modification of Dynamically-Determined Object Attributes",
            aliases=["CVE-2021-32807", "GHSA-qcx9-j53g-ccgf"],
            url="https://gitlab.com/gitlab-org/advisories-community/-/blob/main/pypi/AccessControl/CVE-2021-32807.yml",
        )
        adv2 = self._create_advisory(
            advisory_id="PYSEC-2021-335",
            datasource_id="pypa_importer_v2",
            summary=(
                "The module AccessControl defines security policies for Python code "
                "used in restricted code within Zope applications. Restricted code is "
                "any code that resides in Zopes object database."
            ),
            aliases=["CVE-2021-32807", "GHSA-qcx9-j53g-ccgf"],
            url="https://github.com/pypa/advisory-database/blob/main/vulns/accesscontrol/PYSEC-2021-335.yaml",
        )
        grouped = group_advisories_by_content([adv1, adv2])
        assert len(grouped) == 1
        group = list(grouped.values())[0]
        all_advisories = {group["primary"]} | group["secondary"]
        assert adv1 in all_advisories
        assert adv2 in all_advisories

    def test_alias_chain_merges_three_advisories(self):
        adv_a = self._create_advisory(
            advisory_id="ADV-A",
            datasource_id="source_1",
            summary="Summary A about access control",
            aliases=["CVE-2099-0001"],
            url="https://example.com/a",
        )
        adv_b = self._create_advisory(
            advisory_id="ADV-B",
            datasource_id="source_2",
            summary="Summary B about restricted code",
            aliases=["CVE-2099-0001", "GHSA-xxxx-yyyy-zzzz"],
            url="https://example.com/b",
        )
        adv_c = self._create_advisory(
            advisory_id="ADV-C",
            datasource_id="source_3",
            summary="Summary C about Zope security",
            aliases=["GHSA-xxxx-yyyy-zzzz"],
            url="https://example.com/c",
        )
        grouped = group_advisories_by_content([adv_a, adv_b, adv_c])
        assert len(grouped) == 1

    def test_group_by_summary_similarity(self):
        base_summary = (
            "SQL injection vulnerability in the login form of the web application "
            "allows remote attackers to execute arbitrary SQL commands"
        )
        variant_summary = (
            "SQL injection vulnerability in the login form of the web application "
            "allows remote attackers to execute arbitrary SQL commands via crafted input"
        )
        adv1 = self._create_advisory(
            advisory_id="ADV-SQL-1",
            datasource_id="src_x",
            summary=base_summary,
            url="https://example.com/sql1",
        )
        adv2 = self._create_advisory(
            advisory_id="ADV-SQL-2",
            datasource_id="src_y",
            summary=variant_summary,
            url="https://example.com/sql2",
        )
        grouped = group_advisories_by_content([adv1, adv2])
        assert len(grouped) == 1

    def test_highest_precedence_becomes_primary(self):
        adv_low = self._create_advisory(
            advisory_id="ADV-P1",
            datasource_id="low_src",
            summary="Same summary here",
            aliases=["CVE-2099-9999"],
            url="https://example.com/p1",
        )
        adv_high = self._create_advisory(
            advisory_id="ADV-P2",
            datasource_id="high_src",
            summary="Same summary here",
            aliases=["CVE-2099-9999"],
            url="https://example.com/p2",
        )
        adv_low.precedence = 1
        adv_low.save()
        adv_high.precedence = 10
        adv_high.save()

        grouped = group_advisories_by_content([adv_low, adv_high])
        assert len(grouped) == 1
        group = list(grouped.values())[0]
        assert group["primary"] == adv_high
        assert adv_low in group["secondary"]

    def test_empty_input(self):
        assert group_advisories_by_content([]) == {}

    def test_single_advisory(self):
        adv = self._create_advisory(
            advisory_id="SOLO-1",
            datasource_id="solo_src",
            summary="Lonely advisory",
            url="https://example.com/solo",
        )
        grouped = group_advisories_by_content([adv])
        assert len(grouped) == 1
        group = list(grouped.values())[0]
        assert group["primary"] == adv
        assert group["secondary"] == set()

    def test_none_input(self):
        assert group_advisories_by_content(None) == {}
