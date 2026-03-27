#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import hashlib
import json
from collections import defaultdict

from django.db import transaction

from vulnerabilities.models import AdvisorySet
from vulnerabilities.models import AdvisorySetMember
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import PackageV2
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.utils import normalize_list


class GroupAdvisoriesForPackages(VulnerableCodePipeline):
    """Detect and flag packages that do not exist upstream."""

    pipeline_id = "group_advisories_for_packages"

    @classmethod
    def steps(cls):
        return (cls.group_advisories_for_packages,)

    def group_advisories_for_packages(self):
        group_advisoris_for_packages(logger=self.log)


CONTENT_HASH_CACHE = {}


def merge_advisories(advisories):

    advisories = list(advisories)

    if len(advisories) > 1000:
        return

    content_hash_map = defaultdict(list)

    for adv in advisories:
        if adv.avid in CONTENT_HASH_CACHE:
            content_hash = CONTENT_HASH_CACHE[adv.avid]
        else:
            content_hash = compute_advisory_content_hash(adv)
            CONTENT_HASH_CACHE[adv.avid] = content_hash

        content_hash_map[content_hash].append(adv)

    final_groups = []

    for group in content_hash_map.values():
        groups = get_merged_identifier_groups(group)
        final_groups.extend(groups)

    return final_groups


def compute_advisory_content_hash(adv):
    affected = []
    fixed = []

    for impact in adv.impacted_packages.all():
        affected.extend([pkg.package_url for pkg in impact.affecting_packages.all()])

        fixed.extend([pkg.package_url for pkg in impact.fixed_by_packages.all()])

    normalized_data = {
        "affected_packages": normalize_list(affected),
        "fixed_packages": normalize_list(fixed),
    }

    normalized_json = json.dumps(normalized_data, separators=(",", ":"), sort_keys=True)
    content_hash = hashlib.sha256(normalized_json.encode("utf-8")).hexdigest()
    return content_hash


def get_merged_identifier_groups(advisories):

    identifier_groups = defaultdict(set)

    advisories = list(advisories)

    for adv in advisories:

        identifier_groups[adv.advisory_id].add(adv)

        for alias in adv.aliases.values_list("alias", flat=True):
            identifier_groups[alias].add(adv)

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
    for package in PackageV2.objects.filter(
        type__in=["npm", "pypi", "nuget", "maven", "composer"]
    ).iterator():
        print(package)
        affecting_advisories = AdvisoryV2.objects.latest_affecting_advisories_for_purl(
            purl=package.purl
        ).prefetch_related(
            "aliases",
            "impacted_packages__affecting_packages",
            "impacted_packages__fixed_by_packages",
        )

        fixed_by_advisories = AdvisoryV2.objects.latest_fixed_by_advisories_for_purl(
            purl=package.purl
        ).prefetch_related(
            "aliases",
            "impacted_packages__affecting_packages",
            "impacted_packages__fixed_by_packages",
        )

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
