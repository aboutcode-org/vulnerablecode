from datetime import datetime
import dataclasses
import logging
from typing import Tuple

from django.db import transaction

from vulnerabilities import models
from vulnerabilities.data_source import PackageURL
from vulnerabilities.data_source import Advisory

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
        inferences = self.improver().updated_inferences()
        process_inferences(inferences)
        logger.info("Finished improving using %s.", self.improver.__name__)


@transaction.atomic
def process_inferences(inferences):
    bulk_create_vuln_pkg_refs = set()
    for inference in inferences:
        advisory = inference.advisory
        vuln, vuln_created = _get_or_create_vulnerability(advisory)
        for vuln_ref in advisory.references:
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

        for aff_pkg in advisory.affected_package_urls:
            vulnerable_package, _ = _get_or_create_package(
                aff_pkg
            )
            create_or_update_relation(
                    relation=models.PackageRelatedVulnerability,
                    vulnerability=vuln,
                    source=inference.source,
                    package=vulnerable_package,
                    confidence=inference.confidence)

        for fixed_pkg in advisory.fixed_package_urls:
            patched_package, _ = _get_or_create_package(
                fixed_pkg
            )
            create_or_update_relation(
                    relation=models.PackageRelatedVulnerabilityFix,
                    vulnerability=vuln,
                    source=inference.source,
                    package=vulnerable_package,
                    confidence=inference.confidence)


    models.PackageRelatedVulnerability.objects.bulk_create(
        [i.to_model_object() for i in bulk_create_vuln_pkg_refs]
    )


def _get_or_create_vulnerability(
    advisory: Advisory,
) -> Tuple[models.Vulnerability, bool]:

    vuln, created = models.Vulnerability.objects.get_or_create(
        vulnerability_id=advisory.vulnerability_id
    )  # nopep8
    # Eventually we only want to keep summary from NVD and ignore other descriptions.
    if advisory.summary and vuln.summary != advisory.summary:
        vuln.summary = advisory.summary
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

def create_or_update_relation(relation, vulnerability, source, package, confidence):
    try:
        entry = relation.objects.get(
                vulnerability=vulnerability,
                package=package
                )
        if confidence > entry.confidence:
            entry.source = source
            entry.confidence = confidence
            entry.save()
        logger.debug("%s: Confidence improved for %s R %s, new confidence: %d", relation, package, vulnerability, confidence)

    except relation.DoesNotExist:
        relation.objects.create(
                vulnerability=vulnerability,
                source=source,
                package=package,
                confidence=confidence
                )

