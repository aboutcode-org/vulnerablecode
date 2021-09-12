import json
from typing import List
from itertools import chain

from packageurl import PackageURL
from univers.version_range import VersionRange

from vulnerabilities.data_source import AdvisoryData
from vulnerabilities.data_source import AffectedPackage
from vulnerabilities.data_inference import Inference
from vulnerabilities.data_inference import Improver
from vulnerabilities.data_inference import MAX_CONFIDENCE
from vulnerabilities.models import Advisory


class DefaultImprover(Improver):
    def inferences(self) -> List[Inference]:
        advisories = Advisory.objects.all()

        inferences = []

        for advisory in advisories:
            advisory_data = AdvisoryData.from_dict(json.loads(advisory.data))

            affected_packages = chain.from_iterable(
                [exact_purls(pkg) for pkg in advisory_data.affected_packages]
            )
            fixed_packages = chain.from_iterable(
                [exact_purls(pkg) for pkg in advisory_data.fixed_packages]
            )

            inferences.append(
                Inference(
                    confidence=MAX_CONFIDENCE,
                    summary=advisory_data.summary,
                    vulnerability_id=advisory_data.vulnerability_id,
                    affected_packages=affected_packages,
                    fixed_packages=fixed_packages,
                    references=advisory_data.references,
                )
            )

        return inferences


def exact_purls(pkg: AffectedPackage) -> List[PackageURL]:
    """
    Only AffectedPackages with an equality in their VersionSpecifier are
    considered as exact purls.

    For eg:
    AffectedPackage with version_specifier as scheme:<=2.0 is treated as
    version 2 but the same with scheme:<2.0 is not considered at all as there
    is no info about what comes before the supplied version
    """
    vs = pkg.version_specifier
    purls = []
    for rng in vs.ranges:
        if "=" in rng.operator and not "!" in rng.operator:
            purl = pkg.package._replace(version=rng.version.value)
            purls.append(purl)

    return purls
