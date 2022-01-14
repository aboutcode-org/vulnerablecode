from typing import Iterable
from typing import List
from itertools import chain

from django.db.models.query import QuerySet
from packageurl import PackageURL

from vulnerabilities.data_inference import Improver
from vulnerabilities.data_inference import Inference
from vulnerabilities.data_inference import MAX_CONFIDENCE
from vulnerabilities.data_source import AdvisoryData
from vulnerabilities.data_source import AffectedPackage
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
                vulnerability_id=advisory_data.vulnerability_id,
                confidence=MAX_CONFIDENCE,
                summary=advisory_data.summary,
                affected_purls=affected_purls,
                fixed_purl=fixed_purl,
                references=advisory_data.references,
            )


def get_exact_purls(affected_package: AffectedPackage) -> (List[PackageURL], PackageURL):
    """
    Return purls for fixed and affected packages contained in the given
    AffectedPackage disregarding any ranges.

    Only exact version constraints (ie with an equality) are considered
    For eg:
    >>> purl = {"type": "turtle", "name": "green"}
    >>> vers = "vers:npm/>=2.0.0,<3.0.0 | <1.0.0"
    >>> affected_package = AffectedPackage.from_dict({
    ...     "package": purl,
    ...     "affected_version_range": vers,
    ...     "fixed_version": "5.0.0"
    ... })
    >>> get_exact_purls(affected_package)
    ({PackageURL(type='turtle', namespace=None, name='green', version='2.0.0', qualifiers={}, subpath=None)}, PackageURL(type='turtle', namespace=None, name='green', version='5.0.0', qualifiers={}, subpath=None))
    """
    affected_purls = set()
    all_constraints = affected_package.affected_version_range.constraints
    for constraint in all_constraints:
        if constraint.comparator in ["=", "<=", ">="]:
            affected_purl = affected_package.package._replace(version=str(constraint.version))
            affected_purls.add(affected_purl)
    affected_purls = list(affected_purls)

    fixed_version = affected_package.fixed_version
    fixed_purl = affected_package.package._replace(version=str(fixed_version))

    return affected_purls, fixed_purl
