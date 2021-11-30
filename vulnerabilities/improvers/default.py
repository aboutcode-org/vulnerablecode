import json
from typing import List
from itertools import chain

from packageurl import PackageURL
from django.db.models.query import QuerySet

from vulnerabilities.data_source import AdvisoryData
from vulnerabilities.data_source import AffectedPackage
from vulnerabilities.data_inference import Inference
from vulnerabilities.data_inference import Improver
from vulnerabilities.data_inference import MAX_CONFIDENCE
from vulnerabilities.models import Advisory


class DefaultImprover(Improver):
    """
    This is the first step after running any importer. The inferences generated
    are only a translation of Advisory data returned by the importers into
    full confidence inferences
    """

    @property
    def interesting_advisories(self) -> QuerySet:
        return Advisory.objects.all()

    def get_inferences(self, advisory_data: AdvisoryData) -> List[Inference]:
        inferences = []
        for aff_pkg in advisory_data.affected_packages:
            affected_purls, fixed_purl = exact_purls(aff_pkg)
            inferences.append(
                Inference(
                    vulnerability_id=advisory_data.vulnerability_id,
                    confidence=MAX_CONFIDENCE,
                    summary=advisory_data.summary,
                    affected_purls=affected_purls,
                    fixed_purls=[fixed_purl],
                    references=advisory_data.references,
                )
            )
        return inferences


def exact_purls(aff_pkg: AffectedPackage) -> (List[PackageURL], PackageURL):
    """
    Only AffectedPackages with an equality in their VersionSpecifier are
    considered as exact purls.

    For eg:
    AffectedPackage with version_specifier as scheme:<=2.0 is treated as
    version 2.0 but the same with scheme:<2.0 is not considered at all as there
    is no info about what comes before the supplied version

    Return a list of affected PackageURL and corresponding fixed PackageURL
    """
    vs = aff_pkg.affected_version_specifier
    aff_purls = []
    for rng in vs.ranges:
        if rng.operator in ("=", ">=", "<="):
            aff_purl = aff_pkg.package._replace(version=rng.version.value)
            aff_purls.append(aff_purl)

    fixed_version = aff_pkg.fixed_version.version_string
    fixed_purl = aff_pkg.package._replace(version=fixed_version)

    return aff_purls, fixed_purl
