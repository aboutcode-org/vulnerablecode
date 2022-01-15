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


def get_or_create_vulnerability_and_aliases(vulnerability_id, aliases, summary):
    """
    Get or create vulnerabilitiy and aliases such that all existing and new
    aliases point to the same vulnerability
    """
    existing_vulns = set()
    aliases = set(aliases)
    existing_aliases = set()
    new_aliases = set()
    for alias in aliases:
        alias, created = models.Alias.objects.get_or_create(alias=alias)
        if created:
            new_aliases.add(alias)
        else:
            existing_aliases.add(alias)
            if alias.vulnerability:
                existing_vulns.add(alias.vulnerability)

    # If given set of aliases point to different vulnerabilities in the
    # database, request is malformed
    # TODO: It is possible that all those vulnerabilities are actually
    # the same at data level, figure out a way to merge them
    if len(existing_vulns) > 1:
        logger.warn(
            f"Given aliases {existing_aliases} already exist and do not point "
            "to a single vulnerability. Cannot improve. Skipped."
        )
        return None

    existing_alias_vuln = existing_vulns.pop() if existing_vulns else None

    # If we have been supplied with a vulnerability_id and existing aliases do
    # not have vulnerability_id then create one for all aliases, otherwise use
    # the vulnerability_id from the existing aliases
    if vulnerability_id:
        if not existing_alias_vuln:
            vuln = models.Vulnerability(summary=summary)
            vuln.save()
            for alias in existing_aliases | new_aliases:
                alias.vulnerability = vuln
                alias.save()
            return vuln

        if existing_alias_vuln.vulnerability_id == vulnerability_id:
            # TODO: What to do with the new summary ?
            for alias in new_aliases:
                alias.vulnerability = existing_alias_vuln
                alias.save()
            return existing_alias_vuln

        logger.warn(
            f"Given aliases {existing_aliases!r} already exist and point to existing"
            "vulnerability {existing_alias_vuln}. Unable to create Vulnerability "
            "with vulnerability_id {vulnerability_id}. Skipped"
        )
        return None

    # No vulnerability_id is present, infer one from aliases

    # If all existing aliases point to one vulnerability then point new aliases
    # to that vulnerbility and vulnerability is found
    # TODO: What to do with the new summary ?
    if existing_alias_vuln:
        for alias in new_aliases:
            alias.vulnerability = existing_alias_vuln
            alias.save()
        return existing_alias_vuln

    # No vulnerability already exists for given aliases, create one and
    # point all aliases to this vulnerability
    vuln = models.Vulnerability(summary=summary)
    vuln.save()
    for alias in existing_aliases | new_aliases:
        alias.vulnerability = vuln
        alias.save()
    return vuln
