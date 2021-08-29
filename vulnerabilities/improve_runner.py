from datetime import datetime
import dataclasses
import logging
from typing import Tuple
from typing import Set

from django.db import transaction

from vulnerabilities import models
from vulnerabilities.data_source import PackageURL
from vulnerabilities.data_source import AdvisoryData
from vulnerabilities.data_inference import Inference


logger = logging.getLogger(__name__)


class ImproveRunner:
    """
    The ImproveRunner is responsible to improve the already imported data by a datasource.
    Inferences regarding the data could be generated based on multiple factors.
    All the inferences consist of a confidence score whose threshold could be tuned in user
    settings (.env file)
    """

    def __init__(self, improver):
        self.improver = improver

    def run(self) -> None:
        logger.info("Improving using %s.", self.improver.__name__)
        source = f"{self.improver.__module__}.{self.improver.__qualname__}"
        inferences = self.improver().inferences()
        process_inferences(source=source, inferences=inferences)
        logger.info("Finished improving using %s.", self.improver.__name__)


@transaction.atomic
def process_inferences(source: str, inferences: Set[Inference]):
    bulk_create_vuln_pkg_refs = set()
    for inference in inferences:
        vuln, vuln_created = _get_or_create_vulnerability(inference.vulnerability_id, inference.summary)
        for vuln_ref in inference.references:
            ref, _ = models.VulnerabilityReference.objects.get_or_create(
                vulnerability=vuln, reference_id=vuln_ref.reference_id, url=vuln_ref.url
            )

            for score in vuln_ref.severities:
                models.VulnerabilitySeverity.objects.update_or_create(
                    vulnerability=vuln,
                    scoring_system=score.system.identifier,
                    reference=ref,
                    defaults={"value": str(score.value)},
                )

        for pkg in inference.affected_packages:
            vulnerable_package, _ = _get_or_create_package(pkg)
            models.PackageRelatedVulnerability(
                package=vulnerable_package,
                vulnerability=vuln,
                source=source,
                confidence=inference.confidence,
                fix=False,
            ).update_or_create()

        for pkg in inference.fixed_packages:
            patched_package, _ = _get_or_create_package(pkg)
            models.PackageRelatedVulnerability(
                package=patched_package,
                vulnerability=vuln,
                source=source,
                confidence=inference.confidence,
                fix=True,
            ).update_or_create()

    models.PackageRelatedVulnerability.objects.bulk_create(
        [i.to_model_object() for i in bulk_create_vuln_pkg_refs]
    )


def _get_or_create_vulnerability(
    vulnerability_id, summary
) -> Tuple[models.Vulnerability, bool]:

    vuln, created = models.Vulnerability.objects.get_or_create(
        vulnerability_id=vulnerability_id
    )  # nopep8
    # Eventually we only want to keep summary from NVD and ignore other descriptions.
    if summary and vuln.summary != summary:
        vuln.summary = summary
        vuln.save()

    return vuln, created


def _get_or_create_package(p: PackageURL) -> Tuple[models.Package, bool]:
    query_kwargs = {}
    for key, val in p.to_dict().items():
        if not val:
            if key == "qualifiers":
                query_kwargs[key] = {}
            else:
                query_kwargs[key] = ""
        else:
            query_kwargs[key] = val

    return models.Package.objects.get_or_create(**query_kwargs)


def _package_url_to_package(purl: PackageURL) -> models.Package:
    p = models.Package()
    p.set_package_url(purl)
    return p
