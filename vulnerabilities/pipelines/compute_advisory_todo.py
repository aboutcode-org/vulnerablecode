#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


from aboutcode.pipeline import LoopProgress

from vulnerabilities.models import Advisory
from vulnerabilities.models import AdvisoryToDo
from vulnerabilities.models import Alias
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.pipes import fetchcode_utils
from vulnerabilities.pipes.advisory import advisories_checksum


class ComputeToDo(VulnerableCodePipeline):
    """Compute advisory AdvisoryToDo."""

    pipeline_id = "compute_advisory_todo"

    @classmethod
    def steps(cls):
        return (
            cls.compute_individual_advisory_todo,
            cls.detect_conflicting_advisories,
        )

    def compute_individual_advisory_todo(self):
        advisories = Advisory.objects.all().paginated()
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
        PACKAGE_VERSIONS = {}
        aliases = Alias.objects.filter(alias__istartswith="cve")
        aliases_count = aliases.count()

        self.log(f"Cross validating advisory affected and fixed package for {aliases_count} CVEs")

        progress = LoopProgress(total_iterations=aliases_count, logger=self.log)
        for alias in progress.iter(aliases.paginated()):
            advisories = (
                Advisory.objects.filter(aliases__contains=alias.alias)
                .exclude(advisory_todos__issue_type="MISSING_AFFECTED_AND_FIXED_BY_PACKAGES")
                .distinct()
            )
            purls = get_advisories_purls(advisories=advisories)
            get_package_versions(
                purls=purls,
                package_versions=PACKAGE_VERSIONS,
                logger=self.log,
            )
            check_conflicting_affected_and_fixed_by_packages(
                advisories=advisories,
                package_versions=PACKAGE_VERSIONS,
                purls=purls,
                cve=alias,
                logger=self.log,
            )


def check_missing_summary(advisory, todo_id, logger=None):
    if not advisory.summary:
        todo, created = AdvisoryToDo.objects.get_or_create(
            unique_todo_id=todo_id,
            issue_type="MISSING_SUMMARY",
            issue_detail="",
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
    elif has_fixed_package:
        issue_type = "MISSING_FIXED_BY_PACKAGE"
    todo, created = AdvisoryToDo.objects.get_or_create(
        unique_todo_id=todo_id,
        issue_type=issue_type,
        issue_detail="",
    )
    if created:
        todo.advisories.add(advisory)


def get_package_versions(purls, package_versions, logger=None):
    for purl in purls:
        if purl in package_versions:
            continue
        versions = fetchcode_utils.versions(purl=purl, logger=logger)
        package_versions[purl] = versions


def get_advisories_purls(advisories):
    purls = set()
    for advisory in advisories:
        advisory_obj = advisory.to_advisory_data()
        purls.update([str(i.package) for i in advisory_obj.affected_packages])
    return purls


def check_conflicting_affected_and_fixed_by_packages(
    advisories, package_versions, purls, cve, logger=None
):
    """
    Add appropriate AdvisoryToDo for conflicting affected/fixed packages.

    Compute the comparison matrix for the given set of advisories. Iterate through each advisory
    and compute and store fixed versions and normalized affected versions for each advisory,
    keyed by purl.

    Use the matrix to determine conflicts in affected/fixed versions for each purl. If for any purl
    there is more than one set of fixed versions or more than one set of affected versions,
    it means the advisories have conflicting opinions on the fixed or affected packages.

    Example of comparison matrix:
        {
            "pkg:npm/foo/bar": {
                "affected": {
                    Advisory1: frozenset(NormalizedVersionRange1, NormalizedVersionRange2),
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
        for affected in advisory_obj.affected_packages or []:
            affected_purl = str(affected.package)

            if affected_purl not in purls or not purls[affected_purl]:
                continue

            initialize_sub_matrix(
                matrix=matrix,
                affected_purl=affected_purl,
                advisory=advisory,
            )

            if fixed_version := affected.fixed_version:
                matrix[affected_purl]["fixed"][advisory].add(fixed_version)

            if affected.affected_version_range:
                normalized_vers = affected.affected_version_range.normalize(
                    known_versions=package_versions[affected_purl],
                )
                matrix[affected_purl]["affected"][advisory].add(normalized_vers)

    has_conflicting_affected_packages = False
    has_conflicting_fixed_package = False
    messages = []
    for purl, board in matrix.items():
        fixed = board.get("fixed", {}).values()
        affected = board.get("affected", {}).values()

        # Compare affected_vers set across different advisories.
        unique_set_of_affected_vers = {frozenset(vers) for vers in affected}

        # Compare fixed_version set across different advisories.
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

    todo_id = advisories_checksum(advisories)
    todo, created = AdvisoryToDo.objects.get_or_create(
        unique_todo_id=todo_id,
        issue_type=issue_type,
        issue_detail="\n".join(messages),
    )
    if created:
        todo.advisories.add(*advisories)


def initialize_sub_matrix(matrix, affected_purl, advisory):
    if affected_purl not in matrix:
        matrix[affected_purl] = {
            "affected": {
                advisory: set(),
            },
            "fixed": {
                advisory: set(),
            },
        }
    else:
        if advisory not in matrix[affected_purl]["affected"]:
            matrix[affected_purl]["affected"] = set()
        if advisory not in matrix[affected_purl]["fixed"]:
            matrix[affected_purl]["fixed"] = set()
