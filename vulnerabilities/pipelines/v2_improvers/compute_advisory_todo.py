#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


import json
from collections import Counter
from collections import defaultdict
from itertools import chain

from aboutcode.pipeline import LoopProgress
from django.db.models import Prefetch
from django.utils import timezone
from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import AdvisoryToDoV2
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import ToDoRelatedAdvisoryV2
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.pipes.advisory import advisories_checksum
from vulnerabilities.utils import canonical_value
from vulnerabilities.utils import normalize_text
from vulnerabilities.utils import sha256_digest


class ComputeToDo(VulnerableCodePipeline):
    """Compute ToDos for Advisory."""

    pipeline_id = "compute_advisory_todo_v2"

    @classmethod
    def steps(cls):
        return (
            cls.compute_individual_advisory_todo,
            cls.detect_conflicting_advisories,
        )

    def compute_individual_advisory_todo(self):
        """Create ToDos for missing summary, affected and fixed packages."""

        advisories = (
            AdvisoryV2.objects.todo_excluded()
            .latest_per_avid()
            .exclude(advisory_todos__issue_type="MISSING_SUMMARY")
            .exclude(advisory_todos__issue_type="MISSING_AFFECTED_PACKAGE")
            .exclude(advisory_todos__issue_type="MISSING_FIXED_BY_PACKAGE")
            .exclude(advisory_todos__issue_type="MISSING_AFFECTED_AND_FIXED_BY_PACKAGES")
            .prefetch_related(
                "impacted_packages",
            )
        )
        advisories_count = advisories.count()
        advisory_relation_to_create = {}
        todo_to_create = []
        new_todos_count = 0
        batch_size = 5000

        self.log(
            f"Checking missing summary, affected and fixed packages in {advisories_count} Advisories"
        )
        progress = LoopProgress(
            total_iterations=advisories_count,
            logger=self.log,
            progress_step=10,
        )
        for advisory in progress.iter(advisories.iterator(chunk_size=5000)):
            advisory_todo_id = advisories_checksum(advisories=advisory)
            check_missing_summary(
                advisory=advisory,
                todo_id=advisory_todo_id,
                todo_to_create=todo_to_create,
                advisory_relation_to_create=advisory_relation_to_create,
            )

            check_missing_affected_and_fixed_by_packages(
                advisory=advisory,
                todo_id=advisory_todo_id,
                todo_to_create=todo_to_create,
                advisory_relation_to_create=advisory_relation_to_create,
            )

            if len(todo_to_create) > batch_size:
                new_todos_count += bulk_create_with_m2m(
                    todos=todo_to_create,
                    advisories=advisory_relation_to_create,
                    logger=self.log,
                )
                advisory_relation_to_create.clear()
                todo_to_create.clear()

        new_todos_count += bulk_create_with_m2m(
            todos=todo_to_create,
            advisories=advisory_relation_to_create,
            logger=self.log,
        )

        self.log(
            f"Successfully created {new_todos_count} ToDos for missing summary, affected and fixed packages"
        )

    def detect_conflicting_advisories(self):
        """
        Create ToDos for advisories with conflicting opinions on fixed and affected
        package versions for a vulnerability.
        """
        advisory_relation_to_create = {}
        unfurled_purl_summary = Counter()
        todo_to_create = []
        new_todos_count = 0
        batch_size = 1000
        total_count_conflicting_advisory = 0
        total_package_conflict_count = 0
        total_uncomparable_advisory_count = 0
        total_successfully_compared_advisory_count = 0
        existing_todo_ids = set(
            AdvisoryToDoV2.objects.values_list("related_advisories_id", flat=True)
        )

        advisory_qs = (
            AdvisoryV2.objects.exclude(
                advisory_todos__issue_type="MISSING_AFFECTED_AND_FIXED_BY_PACKAGES"
            )
            .todo_excluded()
            .latest_per_avid()
            .distinct()
            .prefetch_related(
                "impacted_packages",
                "impacted_packages__affecting_packages",
                "impacted_packages__fixed_by_packages",
            )
        )

        cve_aliases = AdvisoryAlias.objects.filter(alias__istartswith="cve").prefetch_related(
            Prefetch("advisories", queryset=advisory_qs, to_attr="filtered_advisories")
        )
        non_cve_aliases = AdvisoryAlias.objects.exclude(alias__istartswith="cve").prefetch_related(
            Prefetch("advisories", queryset=advisory_qs, to_attr="filtered_advisories")
        )
        aliases_count = cve_aliases.count() + non_cve_aliases.count()
        progress = LoopProgress(
            total_iterations=aliases_count,
            logger=self.log,
            progress_step=5,
        )
        self.log(f"Detect conflicting affected and fixed package for {aliases_count} aliases.")
        aliases = chain(
            cve_aliases.iterator(chunk_size=50),
            non_cve_aliases.iterator(chunk_size=50),
        )
        for alias in progress.iter(aliases):
            adv_purl_map = defaultdict(set)
            purl_adv_map = defaultdict(
                lambda: defaultdict(
                    lambda: {
                        "affected": set(),
                        "fixed": set(),
                        "impact_count": 0,
                    }
                )
            )
            unfurled_base_purls = set()
            advisories_with_unfurled_purls = set()

            advisories_with_common_alias = alias.filtered_advisories or []
            known_advisory_ids = [a.id for a in advisories_with_common_alias]
            adv_with_alias_in_adv_id = advisory_qs.filter(advisory_id=alias.alias).exclude(
                id__in=known_advisory_ids
            )
            if not advisories_with_common_alias and not adv_with_alias_in_adv_id.exists():
                continue

            advisories_with_common_alias.extend(adv_with_alias_in_adv_id)
            initial_advisory_group_size = len(advisories_with_common_alias)

            if initial_advisory_group_size < 2:
                total_successfully_compared_advisory_count += initial_advisory_group_size
                continue

            for advisory in advisories_with_common_alias:
                for impact in advisory.impacted_packages.all():
                    base_purl = impact.base_purl
                    adv_purl_map[advisory.avid].add(base_purl)
                    advisory_map = purl_adv_map[base_purl][advisory.avid]
                    advisory_map["affected"].update(
                        p.version for p in impact.affecting_packages.all()
                    )
                    advisory_map["fixed"].update(p.version for p in impact.fixed_by_packages.all())
                    advisory_map["impact_count"] += 1

                    if not impact.last_successful_range_unfurl_at and impact.affecting_vers:
                        unfurled_base_purls.add(base_purl)
                        advisories_with_unfurled_purls.add(advisory.avid)

            # keep only PURLs linked to at least 2 advisories
            comparable_purl_map = {
                purl: value for purl, value in purl_adv_map.items() if len(value) >= 2
            }

            uncomparable_purls = {purl for purl, avids in purl_adv_map.items() if len(avids) < 2}

            comparable_adv_map = {
                adv: (purls - uncomparable_purls)
                for adv, purls in adv_purl_map.items()
                if (purls - uncomparable_purls)
            }

            avids_with_common_alias_and_purl = set(comparable_adv_map)

            advisory_group = {
                adv.avid: adv
                for adv in advisories_with_common_alias
                if adv.avid in avids_with_common_alias_and_purl
            }

            # if any eligible PURL is not unfurled, skip
            if set(comparable_purl_map) & unfurled_base_purls:
                unfurled_purl_summary.update(
                    PackageURL.from_string(up).type for up in unfurled_base_purls
                )

                total_uncomparable_advisory_count += len(advisories_with_unfurled_purls)
                continue

            if not len(advisory_group) > 1:
                total_successfully_compared_advisory_count += len(advisory_group)
                continue

            package_conflict_count, count_conflicting_advisory = (
                check_conflicting_affected_and_fixed_by_packages_for_alias(
                    purl_adv_map=comparable_purl_map,
                    alias=alias,
                    advisories=advisory_group,
                    todo_to_create=todo_to_create,
                    advisory_relation_to_create=advisory_relation_to_create,
                    existing_todo_ids=existing_todo_ids,
                )
            )

            total_successfully_compared_advisory_count += len(advisory_group) - len(
                advisories_with_unfurled_purls
            )
            total_package_conflict_count += package_conflict_count
            total_count_conflicting_advisory += count_conflicting_advisory

            if len(todo_to_create) > batch_size:
                new_todos_count += bulk_create_with_m2m(
                    todos=todo_to_create,
                    advisories=advisory_relation_to_create,
                    logger=self.log,
                )
                advisory_relation_to_create.clear()
                todo_to_create.clear()

        new_todos_count += bulk_create_with_m2m(
            todos=todo_to_create,
            advisories=advisory_relation_to_create,
            logger=self.log,
        )

        self.log(
            f"Successfully compared {total_successfully_compared_advisory_count} advisories, created {new_todos_count} new ToDos for {total_package_conflict_count} "
            f"conflicting affected and fixed packages related to {total_count_conflicting_advisory} advisories."
        )
        self.log(
            f"Could not compare version range for {total_uncomparable_advisory_count} advisory "
            "containing unfurled packages."
        )
        self.log(f"Summary of unfurled PURLs: \n {unfurled_purl_summary}")


def check_missing_summary(
    advisory: AdvisoryV2,
    todo_id,
    todo_to_create,
    advisory_relation_to_create,
):
    alias = advisory.datasource_id.rsplit("/", 1)[-1]
    oldest_advisory_date = advisory.date_published or advisory.date_collected
    if not advisory.summary:
        todo = AdvisoryToDoV2(
            related_advisories_id=todo_id,
            issue_type="MISSING_SUMMARY",
            alias=alias,
            advisories_count=1,
            oldest_advisory_date=oldest_advisory_date,
        )
        advisory_relation_to_create[todo_id] = [advisory]
        todo_to_create.append(todo)


def check_missing_affected_and_fixed_by_packages(
    advisory: AdvisoryV2,
    todo_id,
    todo_to_create,
    advisory_relation_to_create,
):
    """
    Check for missing affected or fixed-by packages in the advisory
    and create appropriate AdvisoryToDo.

    - If both affected and fixed packages are missing add `MISSING_AFFECTED_AND_FIXED_BY_PACKAGES`.
    - If only the affected package is missing add `MISSING_AFFECTED_PACKAGE`.
    - If only the fixed package is missing add `MISSING_FIXED_BY_PACKAGE`.
    """
    has_affected_package = False
    has_fixed_package = False

    for impacted in advisory.impacted_packages.all() or []:
        if not impacted:
            continue

        if has_affected_package and has_fixed_package:
            break
        if not has_affected_package and impacted.affecting_vers:
            has_affected_package = True
        if not has_fixed_package and impacted.fixed_vers:
            has_fixed_package = True

    if has_affected_package and has_fixed_package:
        return

    if not has_affected_package and not has_fixed_package:
        issue_type = "MISSING_AFFECTED_AND_FIXED_BY_PACKAGES"
    elif not has_affected_package:
        issue_type = "MISSING_AFFECTED_PACKAGE"
    elif not has_fixed_package:
        issue_type = "MISSING_FIXED_BY_PACKAGE"

    alias = advisory.datasource_id.rsplit("/", 1)[-1]
    oldest_advisory_date = advisory.date_published or advisory.date_collected
    if issue_type:
        todo = AdvisoryToDoV2(
            related_advisories_id=todo_id,
            issue_type=issue_type,
            alias=alias,
            advisories_count=1,
            oldest_advisory_date=oldest_advisory_date,
        )
        todo_to_create.append(todo)
        advisory_relation_to_create[todo_id] = [advisory]


def compute_version_range_disagreement(adv_map):
    """Compute differences in affected and fixed version sets across advisories."""

    affected_sets = [v["affected"] for v in adv_map.values()]
    fixed_sets = [v["fixed"] for v in adv_map.values()]

    affected_union = set().union(*affected_sets)
    affected_intersection = set.intersection(*affected_sets)

    fixed_union = set().union(*fixed_sets)
    fixed_intersection = set.intersection(*fixed_sets)

    return {
        "affected_union": affected_union,
        "affected_intersection": affected_intersection,
        "affected_disagreement": affected_union - affected_intersection,
        "fixed_union": fixed_union,
        "fixed_intersection": fixed_intersection,
        "fixed_disagreement": fixed_union - fixed_intersection,
    }


def check_conflicting_affected_and_fixed_by_packages_for_alias(
    purl_adv_map,
    alias,
    advisories,
    todo_to_create,
    advisory_relation_to_create,
    existing_todo_ids,
):
    """
    Add appropriate AdvisoryToDo for conflicting affected/fixed packages.

    Compute the comparison matrix for the given set of advisories. Iterate through each purl_adv_map
    and compute and store version range disagreement for conflicting affected/fixed range keyed by PURL.

    Also compute partial curation advisory by merging non conflicting component of conflicting in advisory.
    Conflict package details, partial curation advisory is stored in issue_detail field.

    Example of conflicting_package_details:
        {
            "pkg:maven/org.apache.struts/struts2-core": {
                "avids": [
                    "github_osv_importer_v2/GHSA-mwrx-hx6x-3hhv",
                    "gitlab_importer_v2/maven/org.apache.struts/struts2-core/CVE-2012-0838"
                ],
                "affected_union": {"2.1.8.1", "2.0.8", "2.1.2", "2.0.5", "2.0.11", "2.2.1.1", "2.2.3"},
                "affected_intersection": {"2.1.8.1", "2.0.8", "2.1.2", "2.0.5", "2.0.11", "2.2.3"},
                "affected_disagreement": {"2.2.1.1"},
                "fixed_union": {"2.2.3.1"},
                "fixed_intersection": {"2.2.3.1"},
                "fixed_disagreement": set()
            },
            "pkg:pypi/foobar": {
                "avids": [
                    "pypa_importer_v2/PYSEC-xxxx-18",
                    "pysec_importer_v2/PYSEC-xxxx-18"
                ],
                "affected_union": {"2.1.8.1", "2.0.8"},
                "affected_intersection": {"2.1.8.1", "2.0.8"},
                "affected_disagreement": set(),
                "fixed_union": {"3.1", "3.0"},
                "fixed_intersection": {"3.1"},
                "fixed_disagreement":  {"3.0"},
            },
            ...
        }
    """
    conflicting_package_details = {}

    has_conflicting_affected_packages = False
    has_conflicting_fixed_package = False
    conflicting_advisories = set()
    for purl, adv_map in purl_adv_map.items():
        result = compute_version_range_disagreement(adv_map)
        if not (result["fixed_disagreement"] or result["affected_disagreement"]):
            continue

        if result["fixed_disagreement"]:
            has_conflicting_fixed_package = True
        if result["affected_disagreement"]:
            has_conflicting_affected_packages = True

        conflicting_package_details[purl] = {
            "avids": list(adv_map.keys()),
        }
        conflicting_advisories.update([advisories[avid] for avid in adv_map])
        conflicting_package_details[purl].update(result)

    if not has_conflicting_affected_packages and not has_conflicting_fixed_package:
        return 0, 0

    issue_type = "CONFLICTING_AFFECTED_AND_FIXED_BY_PACKAGES"
    if not has_conflicting_fixed_package:
        issue_type = "CONFLICTING_AFFECTED_PACKAGES"
    elif not has_conflicting_affected_packages:
        issue_type = "CONFLICTING_FIXED_BY_PACKAGES"

    conflicting_advisories = list(conflicting_advisories)
    conflicting_avids = [avd.avid for avd in conflicting_advisories]
    best_purl_avid_impact_map = get_advisory_with_best_impact_for_purls(
        purl_adv_map,
        conflicting_avids,
    )

    partial_merged_advisory = merged_advisory(
        conflicting_advisories, best_purl_avid_impact_map, conflicting_package_details
    )
    conflict_checksum = sha256_digest(canonical_value(conflicting_package_details))

    issue_detail = {
        "alias": alias.alias,
        "conflict_checksum": conflict_checksum,
        "conflict_details": conflicting_package_details,
        "partial_curation_advisory": partial_merged_advisory,
    }

    todo_id = advisories_checksum(conflicting_advisories)

    if todo_id in existing_todo_ids:
        return 0, 0

    existing_todo_ids.add(todo_id)
    conflicting_advisories_count = len(conflicting_advisories)
    conflicting_package_count = len(conflicting_package_details)

    date_published = min(
        (a.date_published for a in conflicting_advisories if a.date_published),
        default=None,
    )
    date_collected = min(
        (a.date_collected for a in conflicting_advisories if a.date_collected),
        default=None,
    )
    todo = AdvisoryToDoV2(
        related_advisories_id=todo_id,
        issue_type=issue_type,
        issue_detail=json.dumps(issue_detail, default=list),
        alias=alias,
        advisories_count=conflicting_advisories_count,
        oldest_advisory_date=date_published or date_collected,
    )
    todo_to_create.append(todo)
    advisory_relation_to_create[todo_id] = conflicting_advisories

    return conflicting_package_count, conflicting_advisories_count


def get_advisory_with_best_impact_for_purls(purl_adv_map, conflicting_avids):
    """
    Return PURL - AVID mapping for packages.

    Select only one advisory per PURL based on maximum impact package count.
    """
    best_purl_avid_map = {}
    for purl, advs in purl_adv_map.items():

        candidates = [
            (avid, values["impact_count"])
            for avid, values in advs.items()
            if avid in conflicting_avids
        ]

        if candidates:
            best_purl_avid_map[purl] = max(candidates, key=lambda x: x[1])
    return best_purl_avid_map


def merged_advisory(advisories, best_purl_avid_impact_map, conflicting_package_details):
    """Merge multiple advisory to one removing any duplicates or conflicting portion of package ranges."""
    merged_adv = {
        "aliases": set(),
        "summary": "",
        "affected_packages": [],
        "references": [],
        "patches": [],
        "severities": [],
        "weaknesses": set(),
    }

    seen_affected = set()
    seen_references = set()
    seen_patches = set()
    seen_severities = set()
    seen_summaries = {}
    merged_summary = []

    for adv in advisories:
        adv_dict = adv.to_advisory_data().to_dict()

        merged_adv["aliases"].update(adv_dict.get("aliases", []))
        merged_adv["weaknesses"].update(adv_dict.get("weaknesses", []))

        if summary := adv_dict.get("summary", "").strip():
            key = normalize_text(summary)
            entry = seen_summaries.setdefault(key, [summary, []])
            entry[1].append(adv.avid)

        for ref in adv_dict.get("references", []):
            update_advisory_item(
                item=ref,
                seen_item=seen_references,
                updatable=merged_adv["references"],
            )

        for patch in adv_dict.get("patches", []):
            update_advisory_item(
                item=patch,
                seen_item=seen_patches,
                updatable=merged_adv["patches"],
            )

        for sev in adv_dict.get("severities", []):
            update_advisory_item(
                item=sev,
                seen_item=seen_severities,
                updatable=merged_adv["severities"],
            )

        for affected in adv_dict.get("affected_packages", []):
            base_purl = PackageURL(**affected["package"]).to_string()

            if base_purl in best_purl_avid_impact_map:
                # if PURL is present in >1 advisory, then choose from best avid mapping.
                # if PURL is not present in best avid mapping, then it means
                # PURL is associated with only one advisory and can be merged as is.
                if best_purl_avid_impact_map[base_purl][0] != adv.avid:
                    continue

            if base_purl in conflicting_package_details:
                conflict = conflicting_package_details[base_purl]

                if conflict["affected_disagreement"]:
                    affected["affected_version_range"] = None

                if conflict["fixed_disagreement"]:
                    affected["fixed_version_range"] = None

            if not (affected["affected_version_range"] or affected["fixed_version_range"]):
                continue

            update_advisory_item(
                item=affected,
                seen_item=seen_affected,
                updatable=merged_adv["affected_packages"],
            )

    for summary, avids in seen_summaries.values():
        merged_summary.append(f"{tuple(sorted(avids))}: {summary}")

    merged_adv["summary"] = "\n".join(merged_summary)
    merged_adv["aliases"] = list(merged_adv["aliases"])
    merged_adv["weaknesses"] = list(merged_adv["weaknesses"])

    merged_adv["advisory_id"] = "PLACEHOLDER_PARTIAL_CURATION_AVID"
    merged_adv["date_published"] = ""
    merged_adv = AdvisoryDataV2.from_dict(merged_adv).to_dict()

    return merged_adv


def update_advisory_item(item, seen_item, updatable):
    digest = hash(canonical_value(item))
    if digest not in seen_item:
        seen_item.add(digest)
        updatable.append(item)


def bulk_create_with_m2m(todos, advisories, logger):
    """Bulk create ToDos and also bulk create M2M ToDo Advisory relationships."""
    if not todos:
        return 0

    start_time = timezone.now()
    try:
        AdvisoryToDoV2.objects.bulk_create(objs=todos, ignore_conflicts=True)
    except Exception as e:
        logger(f"Error creating AdvisoryToDo: {e}")

    new_todos = AdvisoryToDoV2.objects.filter(created_at__gte=start_time)

    relations = [
        ToDoRelatedAdvisoryV2(todo=todo, advisory=advisory)
        for todo in new_todos
        for advisory in advisories[todo.related_advisories_id]
    ]

    try:
        ToDoRelatedAdvisoryV2.objects.bulk_create(relations)
    except Exception as e:
        logger(f"Error creating Advisory ToDo relations: {e}")

    return new_todos.count()
