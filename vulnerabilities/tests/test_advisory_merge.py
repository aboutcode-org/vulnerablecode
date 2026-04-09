#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import hashlib

import pytest

from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import AdvisorySet
from vulnerabilities.models import AdvisorySetMember
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import Group
from vulnerabilities.models import ImpactedPackage
from vulnerabilities.models import PackageV2
from vulnerabilities.utils import compute_advisory_content_hash
from vulnerabilities.utils import delete_and_save_advisory_set
from vulnerabilities.utils import get_advisories_from_groups
from vulnerabilities.utils import get_merged_identifier_groups
from vulnerabilities.utils import merge_advisories
from vulnerabilities.utils import merge_and_save_grouped_advisories


@pytest.mark.django_db
class TestAdvisoryMerge:
    def create_advisory(self, advisory_id, affected_versions, fixed_versions=None, precedence=None):
        unique_content_id = hashlib.sha256(advisory_id.encode()).hexdigest()

        adv = AdvisoryV2.objects.create(
            datasource_id="ghsa",
            advisory_id=advisory_id,
            avid=f"ghsa/{advisory_id}",
            unique_content_id=unique_content_id,
            url="https://example.com/advisory",
            date_collected="2025-07-01T00:00:00Z",
            precedence=precedence,
        )

        pkg = PackageV2.objects.from_purl("pkg:pypi/sample@1.0.0")

        impact = ImpactedPackage.objects.create(
            advisory=adv,
            base_purl="pkg:pypi/sample",
        )

        # affected
        for v in affected_versions:
            p = PackageV2.objects.from_purl(f"pkg:pypi/sample@{v}")
            impact.affecting_packages.add(p)

        # fixed
        if fixed_versions:
            for v in fixed_versions:
                p = PackageV2.objects.from_purl(f"pkg:pypi/sample@{v}")
                impact.fixed_by_packages.add(p)

        return adv

    def test_content_hash_same(self):
        package = PackageV2.objects.from_purl("pkg:pypi/sample@1.0.0")

        adv1 = self.create_advisory("A1", ["1.0"], ["2.0"])
        adv2 = self.create_advisory("A2", ["1.0"], ["2.0"])

        h1 = compute_advisory_content_hash(adv1, package)
        h2 = compute_advisory_content_hash(adv2, package)

        assert h1 == h2

    def test_content_hash_different(self):
        package = PackageV2.objects.from_purl("pkg:pypi/sample@1.0.0")

        adv1 = self.create_advisory("A1", ["1.0"], ["2.0"])
        adv2 = self.create_advisory("A2", ["1.0"], ["3.0"])

        assert compute_advisory_content_hash(adv1, package) != compute_advisory_content_hash(
            adv2, package
        )

    def test_identifier_merging(self):
        adv1 = self.create_advisory("A1", ["1.0"])
        adv2 = self.create_advisory("A2", ["1.0"])

        alias = AdvisoryAlias.objects.create(alias="CVE-123")

        adv1.aliases.add(alias)
        adv2.aliases.add(alias)

        groups = get_merged_identifier_groups([adv1, adv2])

        assert len(groups) == 1
        identifiers, primary, secondary = groups[0]

        assert len(secondary) == 1
        assert primary in [adv1, adv2]

    def test_transitive_merge(self):
        a1 = self.create_advisory("A1", ["1.0"])
        a2 = self.create_advisory("A2", ["1.0"])
        a3 = self.create_advisory("A3", ["1.0"])

        alias_1 = AdvisoryAlias.objects.create(alias="CVE-1")
        alias_2 = AdvisoryAlias.objects.create(alias="CVE-2")

        a1.aliases.add(alias_1)
        a2.aliases.add(alias_1)
        a2.aliases.add(alias_2)
        a3.aliases.add(alias_2)

        groups = get_merged_identifier_groups([a1, a2, a3])

        assert len(groups) == 1

    def test_primary_selection_by_precedence(self):
        a1 = self.create_advisory("A1", ["1.0"], precedence=1)
        a2 = self.create_advisory("A2", ["1.0"], precedence=5)

        alias_1 = AdvisoryAlias.objects.create(alias="CVE-1")

        a1.aliases.add(alias_1)
        a2.aliases.add(alias_1)

        groups = get_merged_identifier_groups([a1, a2])
        _, primary, _ = groups[0]

        assert primary == a2

    def test_get_advisories_from_groups(self):
        adv = self.create_advisory("GHSA-ABC-123", ["1.0"])
        adv.aliases.create(alias="CVE-999")

        groups = get_merged_identifier_groups([adv])
        result = get_advisories_from_groups(groups)

        assert result[0].identifier == "GHSA-ABC-123"
        assert len(result[0].aliases) == 1

    def test_delete_and_save_advisory_set(self):
        package = PackageV2.objects.from_purl("pkg:pypi/sample@1.0.0")

        adv1 = self.create_advisory("A1", ["1.0"])
        adv2 = self.create_advisory("A2", ["1.0"])

        adv1.aliases.create(alias="CVE-1")

        groups = [Group(aliases=set(adv1.aliases.all()), primary=adv1, secondaries=[adv2])]

        delete_and_save_advisory_set(groups, package, relation="affecting")

        assert AdvisorySet.objects.count() == 1
        assert AdvisorySetMember.objects.count() == 2

        advisory_set = AdvisorySet.objects.first()
        members = AdvisorySetMember.objects.filter(advisory_set=advisory_set)

        assert any(m.is_primary for m in members)
        assert any(not m.is_primary for m in members)

    def test_merge_and_save_integration(self):
        package = PackageV2.objects.from_purl("pkg:pypi/sample@1.0.0")

        adv1 = self.create_advisory("A1", ["1.0"], ["2.0"])
        adv2 = self.create_advisory("A2", ["1.0"], ["2.0"])

        alias = AdvisoryAlias.objects.create(alias="CVE-1")

        adv1.aliases.add(alias)
        adv2.aliases.add(alias)

        result = merge_and_save_grouped_advisories(
            package,
            [adv1, adv2],
            relation="test",
        )

        assert len(result) == 1
        assert AdvisorySet.objects.count() == 1
        assert AdvisorySetMember.objects.count() == 2

    def test_merge_advisories_separates_different_content(self):
        package = PackageV2.objects.from_purl("pkg:pypi/sample@1.0.0")

        adv1 = self.create_advisory("A1", ["1.0"], ["2.0"])
        adv2 = self.create_advisory("A2", ["1.0"], ["3.0"])

        groups = merge_advisories([adv1, adv2], package)

        assert len(groups) == 2
