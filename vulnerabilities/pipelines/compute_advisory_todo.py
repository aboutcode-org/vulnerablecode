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

from vulnerabilities.models import Advisory
from vulnerabilities.models import AdvisoryToDo
from vulnerabilities.models import Alias
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.pipes.advisory import advisories_checksum


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
        advisories = Advisory.objects.all().iterator(chunk_size=2000)
        advisories_count = Advisory.objects.all().count()

        self.log(
            f"Checking missing summary, affected and fixed packages in {advisories_count} Advisories"
        )
        progress = LoopProgress(
            total_iterations=advisories_count,
            logger=self.log,
            progress_step=1,
        )
        for advisory in progress.iter(advisories):
            advisory_todo_id = advisories_checksum(advisories=advisory)
            check_missing_summary(
                advisory=advisory,
                todo_id=advisory_todo_id,
                logger=self.log,
            )
            check_missing_affected_and_fixed_by_packages(
                advisory=advisory,
                todo_id=advisory_todo_id,
                logger=self.log,
            )

    def detect_conflicting_advisories(self):
        aliases = Alias.objects.filter(alias__istartswith="cve")
        aliases_count = aliases.count()

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

            check_conflicting_affected_and_fixed_by_packages(
                advisories=advisories,
                cve=alias,
                logger=self.log,
            )


def check_missing_summary(advisory, todo_id, logger=None):
    if not advisory.summary:
        todo, created = AdvisoryToDo.objects.get_or_create(
            related_advisories_id=todo_id,
            issue_type="MISSING_SUMMARY",
        )
        if created:
            todo.advisories.add(advisory)


def check_missing_affected_and_fixed_by_packages(advisory, todo_id, logger=None):
    """
    Check for missing affected or fixed-by packages in the advisory
    and create appropriate AdvisoryToDo.

    - If both affected and fixed packages are missing add `MISSING_AFFECTED_AND_FIXED_BY_PACKAGES`.
    - If only the affected package is missing add `MISSING_AFFECTED_PACKAGE`.
    - If only the fixed package is missing add `MISSING_FIXED_BY_PACKAGE`.
    """
    has_affected_package = False
    has_fixed_package = False
    for affected in advisory.to_advisory_data().affected_packages or []:
        if not affected:
            continue

        if has_affected_package and has_fixed_package:
            break
        if not has_affected_package and affected.affected_version_range:
            has_affected_package = True
        if not has_fixed_package and affected.fixed_version:
            has_fixed_package = True

    if has_affected_package and has_fixed_package:
        return

    if not has_affected_package and not has_fixed_package:
        issue_type = "MISSING_AFFECTED_AND_FIXED_BY_PACKAGES"
    elif not has_affected_package:
        issue_type = "MISSING_AFFECTED_PACKAGE"
    elif not has_fixed_package:
        issue_type = "MISSING_FIXED_BY_PACKAGE"
    todo, created = AdvisoryToDo.objects.get_or_create(
        related_advisories_id=todo_id,
        issue_type=issue_type,
    )
    if created:
        todo.advisories.add(advisory)


def check_conflicting_affected_and_fixed_by_packages(advisories, cve, logger=None):
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
        advisory_obj = advisory.to_advisory_data()
        advisory_id = advisory.unique_content_id
        for affected in advisory_obj.affected_packages or []:
            if not affected:
                continue
            affected_purl = str(affected.package)

            initialize_sub_matrix(
                matrix=matrix,
                affected_purl=affected_purl,
                advisory=advisory,
            )

            if fixed_version := affected.fixed_version:
                matrix[affected_purl]["fixed"][advisory_id].add(str(fixed_version))

            if affected.affected_version_range:
                matrix[affected_purl]["affected"][advisory_id].add(
                    str(affected.affected_version_range)
                )

    has_conflicting_affected_packages = False
    has_conflicting_fixed_package = False
    messages = []
    for purl, board in matrix.items():
        fixed = board.get("fixed", {}).values()
        affected = board.get("affected", {}).values()

        unique_set_of_affected_vers = {frozenset(vers) for vers in affected}
        unique_set_of_fixed_versions = {frozenset(versions) for versions in fixed}

        if len(unique_set_of_affected_vers) > 1:
            has_conflicting_affected_packages = True
            conflicting_affected = json.dumps(unique_set_of_affected_vers, default=list)
            messages.append(
                f"{cve}: {purl} with conflicting affected versions {conflicting_affected}"
            )
        if len(unique_set_of_fixed_versions) > 1:
            has_conflicting_fixed_package = True
            conflicting_fixed = json.dumps(unique_set_of_fixed_versions, default=list)
            messages.append(f"{cve}: {purl} with conflicting fixed version {conflicting_fixed}")

    if not has_conflicting_affected_packages and not has_conflicting_fixed_package:
        return

    issue_type = "CONFLICTING_AFFECTED_AND_FIXED_BY_PACKAGES"
    if not has_conflicting_fixed_package:
        issue_type = "CONFLICTING_AFFECTED_PACKAGES"
    elif not has_conflicting_affected_packages:
        issue_type = "CONFLICTING_FIXED_BY_PACKAGES"

    messages.append("Comparison matrix:")
    messages.append(json.dumps(matrix, indent=2, default=list))
    todo_id = advisories_checksum(advisories)
    todo, created = AdvisoryToDo.objects.get_or_create(
        related_advisories_id=todo_id,
        issue_type=issue_type,
        defaults={
            "issue_detail": "\n".join(messages),
        },
    )
    if created:
        todo.advisories.add(*advisories)


def initialize_sub_matrix(matrix, affected_purl, advisory):
    advisory_id = advisory.unique_content_id
    if affected_purl not in matrix:
        matrix[affected_purl] = {
            "affected": {
                advisory_id: set(),
            },
            "fixed": {
                advisory_id: set(),
            },
        }
    else:
        if advisory not in matrix[affected_purl]["affected"]:
            matrix[affected_purl]["affected"][advisory_id] = set()
        if advisory not in matrix[affected_purl]["fixed"]:
            matrix[affected_purl]["fixed"][advisory_id] = set()
