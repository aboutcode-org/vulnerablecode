import logging
from datetime import datetime
from datetime import timezone
from typing import List
from typing import Tuple

from django.db import transaction

from vulnerabilities import models
from vulnerabilities.data_inference import Inference
from vulnerabilities.data_source import PackageURL
from vulnerabilities.models import Advisory


logger = logging.getLogger(__name__)


class ImproveRunner:
    """ImproveRunner is responsible for populating the database with any
    consumable data. It does so in its ``run`` method by invoking the given
    improver and parsing the returned Inferences into proper database fields
    """

    def __init__(self, improver):
        self.improver = improver

    def run(self) -> None:
        improver = self.improver()
        logger.info(f"Running improver: {improver!r}")
        for advisory in improver.interesting_advisories:
            inferences = improver.get_inferences(advisory_data=advisory.to_advisory_data())
            process_inferences(
                inferences=inferences, advisory=advisory, improver_name=repr(improver)
            )
        logger.info("Finished improving using %s.", self.improver.__name__)


@transaction.atomic
def process_inferences(inferences: List[Inference], advisory: Advisory, improver_name: str):
    """
    An atomic transaction that updates both the Advisory (e.g. date_improved)
    and processes the given inferences to create or update corresponding
    database fields.

    This avoids failing the entire improver when only a single inference is
    erroneous. Also, the atomic transaction for every advisory and its
    inferences makes sure that date_improved of advisory is consistent.
    """

    if not inferences:
        logger.warn(f"Nothing to improve. Source: {improver_name} Advisory id: {advisory.id}")
        return

    logger.info(f"Improving advisory id: {advisory.id}")

    for inference in inferences:
        vuln = get_or_create_vulnerability_and_aliases(
            inference.vulnerability_id, inference.aliases, inference.summary
        )
        if not vuln:
            logger.warn(f"Unable to get vulnerability for inference: {inference!r}")
            continue

        for ref in inference.references:
            ref, _ = models.VulnerabilityReference.objects.get_or_create(
                vulnerability=vuln, reference_id=ref.reference_id, url=ref.url
            )

            for severity in ref.severities:
                obj, updated = models.VulnerabilitySeverity.objects.update_or_create(
                    vulnerability=vuln,
                    scoring_system=severity.system.identifier,
                    reference=ref,
                    defaults={"value": str(severity.value)},
                )
                if updated:
                    logger.info("Severity updated for reference {ref!r} to {severity.value!r}")

        for pkg in inference.affected_purls:
            vulnerable_package, _ = _get_or_create_package(pkg)
            models.PackageRelatedVulnerability(
                vulnerability=vuln,
                package=vulnerable_package,
                created_by=improver_name,
                confidence=inference.confidence,
                fix=False,
            ).update_or_create()

        fixed_package, _ = _get_or_create_package(inference.fixed_purl)
        models.PackageRelatedVulnerability(
            vulnerability=vuln,
            package=fixed_package,
            created_by=improver_name,
            confidence=inference.confidence,
            fix=True,
        ).update_or_create()

    advisory.date_improved = datetime.now(timezone.utc)
    advisory.save()


def _get_or_create_package(p: PackageURL) -> Tuple[models.Package, bool]:
    query_kwargs = {}
    # TODO: this should be revisited as this should best be a model or manager method... and possibly streamlined
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
    # FIXME: this is is likely creating a package from a purl?
    p = models.Package()
    p.set_package_url(purl)
    return p


def get_or_create_vulnerability_and_aliases(vulnerability_id, alias_names, summary):
    """
    Get or create vulnerabilitiy and aliases such that all existing and new
    aliases point to the same vulnerability
    """
    existing_vulns = set()
    alias_names = set(alias_names)
    new_alias_names = set()
    for alias_name in alias_names:
        try:
            alias = models.Alias.objects.get(alias=alias_name)
            existing_vulns.add(alias.vulnerability)
        except models.Alias.DoesNotExist:
            new_alias_names.add(alias_name)

    # If given set of aliases point to different vulnerabilities in the
    # database, request is malformed
    # TODO: It is possible that all those vulnerabilities are actually
    # the same at data level, figure out a way to merge them
    if len(existing_vulns) > 1:
        logger.warn(
            f"Given aliases {alias_names} already exist and do not point "
            f"to a single vulnerability. Cannot improve. Skipped."
        )
        return

    existing_alias_vuln = existing_vulns.pop() if existing_vulns else None

    if (
        existing_alias_vuln
        and vulnerability_id
        and existing_alias_vuln.vulnerability_id != vulnerability_id
    ):
        logger.warn(
            f"Given aliases {alias_names!r} already exist and point to existing"
            f"vulnerability {existing_alias_vuln}. Unable to create Vulnerability "
            f"with vulnerability_id {vulnerability_id}. Skipped"
        )
        return

    if existing_alias_vuln:
        vulnerability = existing_alias_vuln
    elif vulnerability_id:
        try:
            vulnerability = models.Vulnerability.objects.get(vulnerability_id=vulnerability_id)
        except models.Vulnerability.DoesNotExist:
            logger.warn(
                f"Given vulnerability_id: {vulnerability_id} does not exist in the database"
            )
            return
    else:
        vulnerability = models.Vulnerability(summary=summary)
        vulnerability.save()

    if summary and summary != vulnerability.summary:
        logger.warn(
            f"Inconsistent summary for {vulnerability!r}. "
            f"Existing: {vulnerability.summary}, provided: {summary}"
        )

    for alias_name in new_alias_names:
        alias = models.Alias(alias=alias_name, vulnerability=vulnerability)
        alias.save()

    return vulnerability
