#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


from univers.version_constraint import VersionConstraint
from univers.versions import SemverVersion


def get_original_advisory(cve_h2, table):
    adv_segment = [str(cve_h2)]

    for el in cve_h2.next_elements:
        if getattr(el, "name"):
            adv_segment.append(str(el))
        if el == table:
            break

    return "".join(adv_segment)


def parse_summary(cve_h2, table):
    summary = ""
    for el in cve_h2.next_elements:
        if el == table:
            break
        if getattr(el, "name") == "p":
            summary += f"{el.text} "

    return summary


def parse_range(raw_range):
    if ":" in raw_range:
        raw_range = raw_range.partition(":")[-1]

    raw_range = raw_range.replace("to", "-")
    raw_range = raw_range.replace("and", "").replace("later", "")
    raw_range = raw_range.strip()
    parsed_range = []
    for range in raw_range.split(","):
        range = range.strip()
        if not range:
            continue
        if "-" not in range:
            parsed_range.append(
                VersionConstraint(
                    comparator="=",
                    version=SemverVersion(range),
                )
            )
            continue

        lhs, rhs = range.split("-")
        parsed_range.append(
            VersionConstraint(
                comparator=">=",
                version=SemverVersion(lhs.strip()),
            )
        )
        parsed_range.append(
            VersionConstraint(
                comparator="<=",
                version=SemverVersion(rhs.strip()),
            )
        )

    return parsed_range
