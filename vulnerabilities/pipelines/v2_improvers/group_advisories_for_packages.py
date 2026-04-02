#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from typing import List

from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import Group
from vulnerabilities.models import PackageV2
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.pipes.group_advisories import delete_and_save_advisory_set
from vulnerabilities.utils import TYPES_WITH_MULTIPLE_IMPORTERS
from vulnerabilities.utils import merge_advisories


class GroupAdvisoriesForPackages(VulnerableCodePipeline):
    """Group advisories for packages that have multiple importers"""

    pipeline_id = "group_advisories_for_packages"

    @classmethod
    def steps(cls):
        return (cls.group_advisories_for_packages,)

    def group_advisories_for_packages(self):
        group_advisoris_for_packages(logger=self.log)


def group_advisoris_for_packages(logger=None):
    for package in PackageV2.objects.filter(type__in=TYPES_WITH_MULTIPLE_IMPORTERS).iterator():
        print(f"Grouping advisories for package {package.purl}")
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
            affected_groups: List[Group] = merge_advisories(affecting_advisories, package)
            fixed_by_groups: List[Group] = merge_advisories(fixed_by_advisories, package)
            delete_and_save_advisory_set(affected_groups, package, relation="affecting")
            delete_and_save_advisory_set(fixed_by_groups, package, relation="fixing")
        except Exception as e:
            print(f"Failed rebuilding advisory sets for package {package.purl}: {e!r}")
            continue
