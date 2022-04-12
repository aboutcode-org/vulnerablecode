#
# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import re
from typing import Iterable

from django.db.models import Q
from django.db.models.query import QuerySet

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.improver import Improver
from vulnerabilities.improver import Inference
from vulnerabilities.models import VulnerabilityReference

"""
Improvers that look for References without an id and tries to set one.
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
