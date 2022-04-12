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

from typing import Iterable
from typing import List

from django.db.models.query import QuerySet
from packageurl import PackageURL

from vulnerabilities.helpers import evolve_purl
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.improver import MAX_CONFIDENCE
from vulnerabilities.improver import Improver
from vulnerabilities.improver import Inference
from vulnerabilities.models import Advisory


class DefaultImprover(Improver):
    """
    Generate a translation of Advisory data - returned by the importers - into
    full confidence inferences. These are basic database relationships for
    unstructured data present in the Advisory model without any other
    information source.
    """

    @property
    def interesting_advisories(self) -> QuerySet:
        return Advisory.objects.all()

    def get_inferences(self, advisory_data: AdvisoryData) -> Iterable[Inference]:
        for affected_package in advisory_data.affected_packages:
            affected_purls, fixed_purl = get_exact_purls(affected_package)
            yield Inference(
                aliases=advisory_data.aliases,
                confidence=MAX_CONFIDENCE,
                summary=advisory_data.summary,
                affected_purls=affected_purls,
                fixed_purl=fixed_purl,
                references=advisory_data.references,
            )


def get_exact_purls(affected_package: AffectedPackage) -> (List[PackageURL], PackageURL):
    """
    Return a list of affected purls and the fixed package found in the ``affected_package``
    AffectedPackage disregarding any ranges.

    Only exact version constraints (ie with an equality) are considered
    For eg:
    >>> purl = {"type": "turtle", "name": "green"}
    >>> vers = "vers:npm/<1.0.0 | >=2.0.0 | <3.0.0"
    >>> affected_package = AffectedPackage.from_dict({
    ...     "package": purl,
    ...     "affected_version_range": vers,
    ...     "fixed_version": "5.0.0"
    ... })
    >>> got = get_exact_purls(affected_package)
    >>> expected = (
    ...     [PackageURL(type='turtle', namespace=None, name='green', version='2.0.0', qualifiers={}, subpath=None)],
    ...      PackageURL(type='turtle', namespace=None, name='green', version='5.0.0', qualifiers={}, subpath=None)
    ... )
    >>> assert expected == got
    """

    vr = affected_package.affected_version_range
    # We need ``if c`` below because univers returns None as version
    # in case of vers:nginx/*
    # TODO: Revisit after https://github.com/nexB/univers/issues/33
    affected_purls = []
    if vr:
        range_versions = [c.version for c in vr.constraints if c]
        resolved_versions = [v for v in range_versions if v and v in vr]
        for version in resolved_versions:
            affected_purl = evolve_purl(purl=affected_package.package, version=str(version))
            affected_purls.append(affected_purl)

    fixed_purl = affected_package.get_fixed_purl() if affected_package.fixed_version else None

    return affected_purls, fixed_purl
