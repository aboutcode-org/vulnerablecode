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
from typing import List

from django.db import transaction

from vulnerabilities.models import AdvisorySet
from vulnerabilities.models import AdvisorySetMember
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import Group
from vulnerabilities.utils import normalize_list


@transaction.atomic
def delete_and_save_advisory_set(groups, package, relation=None):
    print(f"Grouping advisories for package: {package.purl}")

    AdvisorySet.objects.filter(
        package=package,
        relation_type=relation,
    ).delete()

    advisory_sets = []
    primary_to_group = {}

    for group in groups:
        advisory_sets.append(
            AdvisorySet(
                package=package,
                relation_type=relation,
                primary_advisory_id=group.primary.id,
            )
        )

        primary_to_group[group.primary.id] = group

    AdvisorySet.objects.bulk_create(
        advisory_sets,
        batch_size=5000,
    )

    created_sets = AdvisorySet.objects.filter(
        package=package,
        relation_type=relation,
    ).only("id", "primary_advisory_id")

    advisory_set_map = {adv_set.primary_advisory_id: adv_set.id for adv_set in created_sets}

    alias_through_model = AdvisorySet.aliases.through

    alias_links = []
    memberships = []

    for primary_id, group in primary_to_group.items():
        advisory_set_id = advisory_set_map[primary_id]

        memberships.append(
            AdvisorySetMember(
                advisory_set_id=advisory_set_id,
                advisory_id=group.primary.id,
                is_primary=True,
            )
        )

        memberships.extend(
            AdvisorySetMember(
                advisory_set_id=advisory_set_id,
                advisory_id=adv.id,
                is_primary=False,
            )
            for adv in group.secondaries
        )

        alias_links.extend(
            alias_through_model(
                advisoryset_id=advisory_set_id,
                advisoryalias_id=alias.id,
            )
            for alias in group.aliases
        )

    if alias_links:
        alias_through_model.objects.bulk_create(
            alias_links,
            batch_size=10000,
        )

    if memberships:
        AdvisorySetMember.objects.bulk_create(
            memberships,
            batch_size=10000,
        )

    print(f"Successfully saved advisory sets for package: {package.purl}")


def group_advisory_for_package(package, logger=None):
    """
    Group advisories for a given package and save the advisory sets for the package.
    """
    from vulnerabilities.utils import TYPES_WITH_MULTIPLE_IMPORTERS

    if package.type not in TYPES_WITH_MULTIPLE_IMPORTERS:
        return

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
        group_single_package_with_provided_advisories(
            package, affecting_advisories, fixed_by_advisories
        )
        logger(f"Successfully rebuilt advisory sets for package {package.purl}")
    except Exception as e:
        if logger:
            logger(f"Failed rebuilding advisory sets for package {package.purl}: {e!r}")
        return


def group_single_package_with_provided_advisories(
    package, affecting_advisories, fixed_by_advisories
):
    affected_groups: List[Group] = merge_advisories(affecting_advisories, package)
    fixed_by_groups: List[Group] = merge_advisories(fixed_by_advisories, package)
    delete_and_save_advisory_set(affected_groups, package, relation="affecting")
    delete_and_save_advisory_set(fixed_by_groups, package, relation="fixing")


def compute_advisory_content_hash(adv, version_less_purl_str: str):
    """
    Compute a content hash for an advisory.

    ``version_less_purl_str`` is pre-computed by the caller once and reused
    across all advisories — avoids re-constructing PackageURL N times.
    The impacted_packages relation must already be prefetched with
    ``affecting_packages`` and ``fixed_by_packages`` before calling this.
    """
    affected = []
    fixed = []

    for impact in adv.impacted_packages.all():
        if impact.base_purl != version_less_purl_str:
            continue
        for pkg in impact.affecting_packages.all():
            if pkg.package_url:
                affected.append(pkg.package_url)
        for pkg in impact.fixed_by_packages.all():
            if pkg.package_url:
                fixed.append(pkg.package_url)

    normalized_data = {
        "affected_packages": normalize_list(affected),
        "fixed_packages": normalize_list(fixed),
    }
    normalized_json = json.dumps(normalized_data, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(normalized_json.encode("utf-8")).hexdigest()


def get_merged_identifier_groups(advisories, alias_map: dict):
    """
    Merge advisories based on shared advisory_id or alias.

    ``alias_map`` is a dict[adv.id -> list[AdvisoryAlias]] pre-built by the
    caller from a single bulk query — eliminates per-advisory alias lookups.

    Uses a union-find (DSU) structure instead of the original O(n²) list-scan
    merge, reducing merge cost to O(n·α(n)).
    """
    from vulnerabilities.models import Group

    advisories = list(advisories)
    if not advisories:
        return []

    parent = list(range(len(advisories)))
    rank = [0] * len(advisories)

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        rx, ry = find(x), find(y)
        if rx == ry:
            return
        if rank[rx] < rank[ry]:
            rx, ry = ry, rx
        parent[ry] = rx
        if rank[rx] == rank[ry]:
            rank[rx] += 1

    identifier_to_idx: dict[str, int] = {}

    for i, adv in enumerate(advisories):
        identifiers = [adv.advisory_id] + [alias.alias for alias in alias_map.get(adv.id, [])]
        for ident in identifiers:
            if ident in identifier_to_idx:
                union(i, identifier_to_idx[ident])
            else:
                identifier_to_idx[ident] = i

    root_to_group: dict[int, list] = defaultdict(list)
    for i, adv in enumerate(advisories):
        root_to_group[find(i)].append(adv)

    final_groups: list[Group] = []

    for group_members in root_to_group.values():
        aliases = set()
        for adv in group_members:
            aliases.update(alias_map.get(adv.id, []))

        primary = max(
            group_members,
            key=lambda a: a.precedence if a.precedence is not None else -1,
        )
        secondaries = [a for a in group_members if a is not primary]
        final_groups.append(Group(aliases=aliases, primary=primary, secondaries=secondaries))

    return final_groups


def merge_advisories(advisories, package):
    """
    Merge advisories based on content hash and identifiers.

    Builds the alias map once up-front from the already-prefetched queryset
    so every downstream call shares a single in-memory dict.
    """
    from packageurl import PackageURL

    advisories = list(advisories)
    if not advisories:
        return []

    version_less_purl_str = str(
        PackageURL(
            type=package.type,
            namespace=package.namespace,
            name=package.name,
            qualifiers=package.qualifiers,
            subpath=package.subpath,
        )
    )

    alias_map: dict[int, list] = defaultdict(list)
    for adv in advisories:
        alias_map[adv.id] = list(adv.aliases.all())

    content_hash_map: dict[str, list] = defaultdict(list)
    for adv in advisories:
        content_hash = compute_advisory_content_hash(adv, version_less_purl_str)
        content_hash_map[content_hash].append(adv)

    final_groups: list[Group] = []
    for group in content_hash_map.values():
        groups = get_merged_identifier_groups(group, alias_map)
        final_groups.extend(groups)

    return final_groups
