#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django import template
from packageurl import PackageURL

register = template.Library()


@register.filter
def format_diff_for_ui(changes) -> dict:
    """
    Example:
        {
            'affected_packages': {
                'added': [{'package': {'type': 'pypi', 'name': 'requests', 'version': '2.25.0'}, 'affected_version_range': '==2.25.0', 'fixed_version_range': '==2.25.1'}],
                'removed': [{'package': {'type': 'pypi', 'name': 'requests', 'version': '2.24.0'}, 'affected_version_range': '==2.24.0', 'fixed_version_range': '==2.24.1'}]
            }
        }
    should result in:
            {
                'Affected Packages': {
                    'added': [{'header': 'Affected package', 'attributes': [('PURL', 'pkg:pypi/requests@2.25.0'), ('Affected version', '==2.25.0'), ('Fixed Version', '==2.25.1')] }],
                    'removed': [{'header': 'Affected package', 'attributes': [('PURL', 'pkg:pypi/requests@2.24.0'), ('Affected version', '==2.24.0'), ('Fixed Version', '==2.24.1')] }]
                }
            }
    """
    formatted = {}

    for field, change in changes.items():
        label = field.replace("_", " ").title()

        if "old" in change or "new" in change:
            formatted[label] = change
            continue

        formatted[label] = {"added": [], "removed": []}

        for change_type in ["added", "removed"]:
            for item in change.get(change_type, []):
                if field == "affected_packages":
                    attributes = []

                    if package := item.get("package"):
                        package_string = (
                            str(PackageURL(**package))
                            if isinstance(package, dict)
                            else str(package)
                        )
                        attributes.append(("PURL", package_string))

                    if affected_version_range := item.get("affected_version_range"):
                        attributes.append(("Affected version", affected_version_range))

                    if fixed_version_range := item.get("fixed_version_range"):
                        attributes.append(("Fixed Version", fixed_version_range))

                    formatted[label][change_type].append(
                        {"header": "Affected package", "attributes": attributes}
                    )

                elif field == "references":
                    attributes = []

                    if reference_url := item.get("url"):
                        attributes.append(("URL", reference_url))

                    if reference_id := item.get("reference_id"):
                        attributes.append(("ID", reference_id))

                    formatted[label][change_type].append(
                        {"header": "Reference", "attributes": attributes}
                    )

                elif field == "severities":
                    attributes = []

                    if scoring_system := item.get("system") or item.get("scoring_system"):
                        scoring_system_string = str(scoring_system)
                        if "cvss" in scoring_system_string.lower():
                            scoring_system_string = scoring_system_string.upper()
                        else:
                            scoring_system_string = scoring_system_string.replace("_", " ").title()
                        attributes.append(("System", scoring_system_string))

                    if severity_value := item.get("value"):
                        attributes.append(("Value", severity_value))

                    if scoring_elements := item.get("scoring_elements"):
                        attributes.append(("Elements", scoring_elements))

                    formatted[label][change_type].append(
                        {"header": "Severity", "attributes": attributes}
                    )

                elif field == "patches":
                    attributes = []

                    if patch_url := (item.get("url") or item.get("repository")):
                        attributes.append(("URL", patch_url))

                    if patch_commit := item.get("commit"):
                        attributes.append(("Commit", patch_commit))

                    formatted[label][change_type].append(
                        {"header": "Patch", "attributes": attributes}
                    )

                else:
                    formatted[label][change_type].append(item)

    return formatted
