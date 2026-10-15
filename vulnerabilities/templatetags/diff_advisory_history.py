#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django import template

from vulnerabilities.models import AdvisoryHistoryDiff

register = template.Library()


@register.filter
def format_diff_for_ui(diff: AdvisoryHistoryDiff) -> dict:
    formatted = {}

    if diff.summary_added or diff.summary_removed:
        formatted["Summary"] = {"old": diff.summary_removed, "new": diff.summary_added}

    if diff.url_added or diff.url_removed:
        formatted["Url"] = {"old": diff.url_removed, "new": diff.url_added}

    def _process_added_removed(label, added_qs, removed_qs, formatter):
        added = [formatter(item) for item in added_qs]
        removed = [formatter(item) for item in removed_qs]
        if added or removed:
            formatted[label] = {"added": added, "removed": removed}

    def format_severity(severity):
        scoring_system_string = str(severity.scoring_system)
        if "cvss" in scoring_system_string.lower():
            scoring_system_string = scoring_system_string.upper()
        else:
            scoring_system_string = scoring_system_string.replace("_", " ").title()

        attrs = [("System", scoring_system_string)]
        if severity.value:
            attrs.append(("Value", severity.value))
        if severity.scoring_elements:
            attrs.append(("Elements", severity.scoring_elements))
        return {"header": "Severity", "attributes": attrs}

    _process_added_removed(
        "Severities", diff.added_severities.all(), diff.removed_severities.all(), format_severity
    )

    def format_package(package):
        attrs = [("PURL", package.base_purl)]
        if package.affecting_vers:
            attrs.append(("Affected version", package.affecting_vers))
        if package.fixed_vers:
            attrs.append(("Fixed Version", package.fixed_vers))
        return {"header": "Affected package", "attributes": attrs}

    _process_added_removed(
        "Affected Packages",
        diff.added_impacted_packages.all(),
        diff.removed_impacted_packages.all(),
        format_package,
    )

    def format_reference(reference):
        attrs = []
        if reference.url:
            attrs.append(("URL", reference.url))
        if reference.reference_id:
            attrs.append(("ID", reference.reference_id))
        return {"header": "Reference", "attributes": attrs}

    _process_added_removed(
        "References", diff.added_references.all(), diff.removed_references.all(), format_reference
    )

    def format_patch(patch):
        attrs = []
        if patch.url or patch.repository:
            attrs.append(("URL", patch.url or patch.repository))
        if patch.commit:
            attrs.append(("Commit", patch.commit))
        return {"header": "Patch", "attributes": attrs}

    _process_added_removed(
        "Patches", diff.added_patches.all(), diff.removed_patches.all(), format_patch
    )

    _process_added_removed(
        "Weaknesses",
        diff.added_weaknesses.all(),
        diff.removed_weaknesses.all(),
        lambda weakness: weakness.cwe_id,
    )

    _process_added_removed(
        "Aliases", diff.added_aliases.all(), diff.removed_aliases.all(), lambda alias: alias.alias
    )

    return formatted
