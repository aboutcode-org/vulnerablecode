#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from vulnerabilities.models import PackageV2
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.pipes.group_advisories import group_advisory_for_package
from vulnerabilities.utils import TYPES_WITH_MULTIPLE_IMPORTERS


class GroupAdvisoriesForPackages(VulnerableCodePipeline):
    """Group advisories for packages that have multiple importers"""

    pipeline_id = "group_advisories_for_packages"
    run_once = True

    @classmethod
    def steps(cls):
        return (cls.group_advisories_for_packages,)

    def group_advisories_for_packages(self):
        group_advisoris_for_packages(logger=self.log)


def group_advisoris_for_packages(logger=None):
    for package in PackageV2.objects.filter(type__in=TYPES_WITH_MULTIPLE_IMPORTERS).iterator():
        group_advisory_for_package(package, logger=logger)
