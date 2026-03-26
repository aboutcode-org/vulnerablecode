#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from collections import defaultdict

from django.db import transaction

from vulnerabilities.models import AdvisorySet
from vulnerabilities.models import AdvisorySetMember
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import PackageV2
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.utils import compute_advisory_content


class GroupAdvisoriesForPackages(VulnerableCodePipeline):
    """Detect and flag packages that do not exist upstream."""

    pipeline_id = "group_advisories_for_packages"

    @classmethod
    def steps(cls):
        return (cls.group_advisories_for_packages,)

    def group_advisories_for_packages(self):
        group_advisoris_for_packages(logger=self.log)


def merge_advisories(advisories):

    advisories = list(advisories)

    print(len(advisories))

    content_hash_map = defaultdict(list)
    result_groups = []

    for adv in advisories:
        print(adv.avid)
        if adv.advisory_content_hash:
            content_hash_map[adv.advisory_content_hash].append(adv)
        else:
            content_hash = compute_advisory_content(advisory_data=adv)
            if content_hash:
                content_hash_map[content_hash].append(adv)
            else:
                result_groups.append([adv])

    final_groups = []

    for group in content_hash_map.values():
        groups = get_merged_identifier_groups(group)
        final_groups.extend(groups)

    return final_groups


def get_merged_identifier_groups(advisories):

    identifier_groups = defaultdict(set)
    advisory_to_identifiers = defaultdict(set)

    advisories = list(advisories)

    for adv in advisories:

        identifier_groups[adv.advisory_id].add(adv)
        advisory_to_identifiers[adv].add(adv.advisory_id)

        for alias in adv.aliases.all():
            identifier_groups[alias.alias].add(adv)
            advisory_to_identifiers[adv].add(alias.alias)

    groups = [set(advs) for advs in identifier_groups.values() if len(advs) > 1]

    merged = []

    for group in groups:
        group = set(group)

        i = 0
        while i < len(merged):
            if group & merged[i]:
                group |= merged[i]
                merged.pop(i)
            else:
                i += 1

        merged.append(group)

    all_grouped = set()
    for g in merged:
        all_grouped |= g

    for adv in advisories:
        if adv not in all_grouped:
            merged.append({adv})

    final_groups = []

    for group in merged:
        identifiers = set()
        for adv in group:
            for alias in adv.aliases.values_list("alias", flat=True):
                identifiers.add(alias)

        primary = max(group, key=lambda a: a.precedence if a.precedence is not None else -1)

        secondary = [a for a in group if a != primary]

        final_groups.append((identifiers, primary, secondary))

    return final_groups


def group_advisoris_for_packages(logger=None):
    for package in PackageV2.objects.iterator():
        affecting_advisories = AdvisoryV2.objects.latest_affecting_advisories_for_purl(
            purl=package.purl
        ).prefetch_related("aliases")

        fixed_by_advisories = AdvisoryV2.objects.latest_fixed_by_advisories_for_purl(
            purl=package.purl
        ).prefetch_related("aliases")

        try:
            delete_and_save_advisory_set(package, affecting_advisories, relation="affecting")
            delete_and_save_advisory_set(package, fixed_by_advisories, relation="fixing")
        except Exception as e:
            print(f"Failed rebuilding advisory sets for package {package.purl}: {e!r}")
            continue


@transaction.atomic
def delete_and_save_advisory_set(package, advisories, relation=None):
    AdvisorySet.objects.filter(package=package, relation_type=relation).delete()

    groups = merge_advisories(advisories)

    membership_to_create = []

    for identifiers, primary, secondary in groups:

        advisory_set = AdvisorySet.objects.create(
            package=package,
            relation_type=relation,
            identifiers=list(identifiers),
            primary_advisory=primary,
        )

        membership_to_create.append(
            AdvisorySetMember(
                advisory_set=advisory_set,
                advisory=primary,
                is_primary=True,
            )
        )

        for adv in secondary:
            membership_to_create.append(
                AdvisorySetMember(
                    advisory_set=advisory_set,
                    advisory=adv,
                    is_primary=False,
                )
            )

    AdvisorySetMember.objects.bulk_create(membership_to_create)
