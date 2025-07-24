#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


import json

from aboutcode.pipeline import LoopProgress
from django.utils import timezone

from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import AdvisoryToDoV2
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import ImpactedPackage
from vulnerabilities.models import ToDoRelatedAdvisoryV2
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.pipes.advisory import advisories_checksum_v2


class ComputeToDo(VulnerableCodePipeline):
    """Compute ToDos for Advisory."""

    pipeline_id = "compute_advisory_todo"

    @classmethod
    def steps(cls):
        return (
            cls.compute_individual_advisory_todo,
            cls.detect_conflicting_advisories,
        )

    def compute_individual_advisory_todo(self):
        """Create ToDos for missing summary, affected and fixed packages."""

        advisories = AdvisoryV2.objects.all()
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
            progress_step=1,
        )
        for advisory in progress.iter(advisories.iterator(chunk_size=5000)):
            advisory_todo_id = advisories_checksum_v2(advisories=advisory)
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
        aliases = AdvisoryAlias.objects.filter(alias__istartswith="cve")
        aliases_count = aliases.count()
        advisory_relation_to_create = {}
        todo_to_create = []
        new_todos_count = 0
        batch_size = 5000

        self.log(f"Cross validating advisory affected and fixed package for {aliases_count} CVEs")

        progress = LoopProgress(
            total_iterations=aliases_count,
            logger=self.log,
            progress_step=1,
        )
        for alias in progress.iter(aliases.iterator(chunk_size=2000)):
            advisories = alias.advisories.exclude(
                advisory_todos__issue_type="MISSING_AFFECTED_AND_FIXED_BY_PACKAGES"
            ).distinct()

            check_conflicting_affected_and_fixed_by_packages_for_alias(
                advisories=advisories,
                cve=alias,
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
            f"Successfully created {new_todos_count} ToDos for conflicting affected and fixed packages"
        )


def check_missing_summary(
    advisory: AdvisoryV2,
    todo_id,
    todo_to_create,
    advisory_relation_to_create,
):
    if not advisory.summary:
        todo = AdvisoryToDoV2(
            related_advisories_id=todo_id,
            issue_type="MISSING_SUMMARY",
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

    if issue_type:
        todo = AdvisoryToDoV2(
            related_advisories_id=todo_id,
            issue_type=issue_type,
        )
        todo_to_create.append(todo)
        advisory_relation_to_create[todo_id] = [advisory]


def check_conflicting_affected_and_fixed_by_packages_for_alias(
    advisories,
    cve,
    todo_to_create,
    advisory_relation_to_create,
):
    """
    Add appropriate AdvisoryToDo for conflicting affected/fixed packages.

    Compute the comparison matrix for the given set of advisories. Iterate through each advisory
    and compute and store fixed versions and affected versionrange for each advisory,
    keyed by purl.

    Use the matrix to determine conflicts in affected/fixed versions for each purl. If for any purl
    there is more than one set of fixed versions or more than one set of affected versions,
    it means the advisories have conflicting opinions on the fixed or affected packages.

    Example of comparison matrix:
        {
            "pkg:npm/foo/bar": {
                "affected": {
                    Advisory1: frozenset(VersionRange1, VersionRange2),
                    Advisory2: frozenset(...),
                },
                "fixed": {
                    Advisory1: frozenset(Version1, Version2),
                    Advisory2: frozenset(...),
                },
            },
            "pkg:pypi/foobar": {
                "affected": {
                    Advisory1: frozenset(...),
                    Advisory2: frozenset(...),
                },
                "fixed": {
                    Advisory1: frozenset(...),
                    Advisory2: frozenset(...),
                },
            },
            ...
        }
    """
    matrix = {}
    for advisory in advisories:
        advisory_id = advisory.unique_content_id
        for impacted in advisory.impacted_packages.all() or []:
            if not impacted:
                continue
            affected_purl = str(impacted.base_purl)

            initialize_sub_matrix(
                matrix=matrix,
                affected_purl=affected_purl,
                advisory=advisory,
            )

            if fixed_version := impacted.fixed_vers:
                matrix[affected_purl]["fixed"][advisory_id].add(str(fixed_version))

            if impacted.affecting_vers:
                matrix[affected_purl]["affected"][advisory_id].add(str(impacted.affecting_vers))

    has_conflicting_affected_packages = False
    has_conflicting_fixed_package = False
    messages = []
    for purl, board in matrix.items():
        fixed = board.get("fixed", {}).values()
        impacted = board.get("affected", {}).values()

        unique_set_of_affected_vers = {frozenset(vers) for vers in impacted}
        unique_set_of_fixed_versions = {frozenset(versions) for versions in fixed}

        if len(unique_set_of_affected_vers) > 1:
            has_conflicting_affected_packages = True
            messages.append(
                f"{cve}: {purl} with conflicting affected versions {unique_set_of_affected_vers}"
            )
        if len(unique_set_of_fixed_versions) > 1:
            has_conflicting_fixed_package = True
            messages.append(
                f"{cve}: {purl} with conflicting fixed version {unique_set_of_fixed_versions}"
            )

    if not has_conflicting_affected_packages and not has_conflicting_fixed_package:
        return

    issue_type = "CONFLICTING_AFFECTED_AND_FIXED_BY_PACKAGES"
    if not has_conflicting_fixed_package:
        issue_type = "CONFLICTING_AFFECTED_PACKAGES"
    elif not has_conflicting_affected_packages:
        issue_type = "CONFLICTING_FIXED_BY_PACKAGES"

    issue_detail = {
        "Conflict summary": messages,
        "Conflict matrix": matrix,
    }

    todo_id = advisories_checksum_v2(advisories)
    todo = AdvisoryToDoV2(
        related_advisories_id=todo_id,
        issue_type=issue_type,
        issue_detail=json.dumps(issue_detail, default=list),
    )
    todo_to_create.append(todo)
    advisory_relation_to_create[todo_id] = list(advisories)


def initialize_sub_matrix(matrix, affected_purl, advisory):
    advisory_id = advisory.unique_content_id
    if affected_purl not in matrix:
        matrix[affected_purl] = {
            "affected": {advisory_id: set()},
            "fixed": {advisory_id: set()},
        }
    else:
        if advisory not in matrix[affected_purl]["affected"]:
            matrix[affected_purl]["affected"][advisory_id] = set()
        if advisory not in matrix[affected_purl]["fixed"]:
            matrix[affected_purl]["fixed"][advisory_id] = set()


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
