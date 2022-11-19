#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import re
from typing import Iterable

from django.db.models import Q
from django.db.models.query import QuerySet

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.improver import Improver
from vulnerabilities.improver import Inference
from vulnerabilities.models import VulnerabilityReference

"""
Improver that looks for CVE References without an id and tries to set one.
"""


class CveIdImprover(Improver):
    """
    Add a CVE reference id when missing.
    Note that we only look for uppercase CVE for now
    """

    @property
    def interesting_advisories(self) -> QuerySet:
        return VulnerabilityReference.objects.filter(
            Q(reference_id__isnull=True) | Q(reference_id__exact=""),
            url__contains="nvd.nist.gov/vuln/detail/CVE-",
        )

    def get_inferences(self, advisory_data: AdvisoryData) -> Iterable[Inference]:
        cve_pattern = re.compile(r"(CVE-\d{4}-\d{4,7})").search
        for ref in self.interesting_advisories:
            cve_match = cve_pattern(ref.url)
            if cve_match:
                cve = cve_match.group()
                ref.reference_id = cve
                ref.save()
