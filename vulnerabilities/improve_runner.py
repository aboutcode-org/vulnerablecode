#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from traceback import format_exc as traceback_format_exc
from typing import List

from django.core.exceptions import ValidationError
from django.db import transaction

from vulnerabilities.importers import IMPORTERS_REGISTRY
from vulnerabilities.improver import Inference
from vulnerabilities.models import Advisory
from vulnerabilities.models import Alias
from vulnerabilities.models import Package
from vulnerabilities.models import PackageRelatedVulnerability
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityChangeLog
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import VulnerabilityRelatedReference
from vulnerabilities.models import VulnerabilitySeverity
from vulnerabilities.models import Weakness
from vulnerabilities.utils import get_importer_name

logger = logging.getLogger(__name__)


class ImproveRunner:
    """
    ImproveRunner is responsible for populating the database with any
    consumable data. It does so in its ``run`` method by invoking the given
    improver and parsing the returned Inferences into proper database fields
    """

    def __init__(self, improver_class):
        self.improver_class = improver_class

    def run(self) -> None:
        improver = self.improver_class()
        logger.info(f"Running improver: {improver.qualified_name}")
        for advisory in improver.interesting_advisories:
            logger.info(f"Processing advisory: {advisory!r}")
            try:
                inferences = improver.get_inferences(advisory_data=advisory.to_advisory_data())
                process_inferences(
                    inferences=inferences,
                    advisory=advisory,
                    improver_name=improver.qualified_name,
                )
            except Exception as e:
                logger.info(f"Failed to process advisory: {advisory!r} with error {e!r}")
        logger.info("Finished improving using %s.", self.improver_class.qualified_name)


@transaction.atomic
def process_inferences(
    inferences: List[Inference],
    advisory: Advisory,
    improver_name: str,
):
    """
    Return number of inferences processed.
    An atomic transaction that updates both the Advisory (e.g. date_imported)
    and processes the given inferences to create or update corresponding
    database fields.

    This avoids failing the entire improver when only a single inference is
    erroneous. Also, the atomic transaction for every advisory and its
    inferences makes sure that date_imported of advisory is consistent.
    """
    inferences_processed_count = 0

    if not inferences:
        logger.warning(f"Nothing to improve. Source: {improver_name} Advisory id: {advisory.id}")
        return inferences_processed_count

    logger.info(f"Improving advisory id: {advisory.id}")

    for inference in inferences:
        vulnerability = get_or_create_vulnerability_and_aliases(
            vulnerability_id=inference.vulnerability_id,
            aliases=inference.aliases,
            summary=inference.summary,
            advisory=advisory,
        )

        if not vulnerability:
            logger.warning(f"Unable to get vulnerability for inference: {inference!r}")
            continue

        for ref in inference.references:

            reference = VulnerabilityReference.objects.get_or_none(
                reference_id=ref.reference_id,
                reference_type=ref.reference_type,
                url=ref.url,
            )

            if not reference:
                reference = create_valid_vulnerability_reference(
                    reference_id=ref.reference_id,
                    reference_type=ref.reference_type,
                    url=ref.url,
                )
                if not reference:
                    continue

            VulnerabilityRelatedReference.objects.update_or_create(
                reference=reference,
                vulnerability=vulnerability,
            )

            for severity in ref.severities:
                _vs, updated = VulnerabilitySeverity.objects.update_or_create(
                    scoring_system=severity.system.identifier,
                    reference=reference,
                    defaults={
                        "value": str(severity.value),
                        "scoring_elements": str(severity.scoring_elements),
                    },
                )
                if updated:
                    logger.info(
                        f"Severity updated for reference {ref!r} to value: {severity.value!r} "
                        f"and scoring_elements: {severity.scoring_elements!r}"
                    )

        for affected_purl in inference.affected_purls or []:
            vulnerable_package, created = Package.objects.get_or_create_from_purl(
                purl=affected_purl
            )
            PackageRelatedVulnerability(
                vulnerability=vulnerability,
                package=vulnerable_package,
                created_by=improver_name,
                confidence=inference.confidence,
                fix=False,
            ).update_or_create(
                advisory=advisory,
            )

        if inference.fixed_purl:
            fixed_package, created = Package.objects.get_or_create_from_purl(
                purl=inference.fixed_purl
            )
            PackageRelatedVulnerability(
                vulnerability=vulnerability,
                package=fixed_package,
                created_by=improver_name,
                confidence=inference.confidence,
                fix=True,
            ).update_or_create(
                advisory=advisory,
            )

        if inference.weaknesses and vulnerability:
            for cwe_id in inference.weaknesses:
                cwe_obj, created = Weakness.objects.get_or_create(cwe_id=cwe_id)
                cwe_obj.vulnerabilities.add(vulnerability)
                cwe_obj.save()

        inferences_processed_count += 1
    return inferences_processed_count


def create_valid_vulnerability_reference(url, reference_type="", reference_id=None):
    """
    Create and return a new validated VulnerabilityReference from a
    ``url`` and ``reference_id``.
    Return None and log a warning if this is not a valid reference.
    """
    reference = VulnerabilityReference(
        reference_id=reference_id,
        reference_type=reference_type,
        url=url,
    )

    try:
        reference.full_clean()
    except ValidationError as e:
        logger.warning(f"Invalid vulnerability reference: {reference!r}: {e}")
        return

    reference.save()
    return reference


def get_or_create_vulnerability_and_aliases(
    aliases: List[str], vulnerability_id=None, summary=None, advisory=None
):
    """
    Get or create vulnerabilitiy and aliases such that all existing and new
    aliases point to the same vulnerability
    """
    aliases = set(alias.strip() for alias in aliases if alias and alias.strip())
    new_alias_names, existing_vulns = get_vulns_for_aliases_and_get_new_aliases(aliases)

    # All aliases must point to the same vulnerability
    vulnerability = None
    if existing_vulns:
        if len(existing_vulns) != 1:
            vcids = ", ".join(v.vulnerability_id for v in existing_vulns)
            logger.error(
                f"Cannot create vulnerability. "
                f"Aliases {aliases} already exist and point "
                f"to multiple vulnerabilities {vcids}."
            )
            return
        else:
            vulnerability = existing_vulns.pop()

            if vulnerability_id and vulnerability.vulnerability_id != vulnerability_id:
                logger.error(
                    f"Cannot create vulnerability. "
                    f"Aliases {aliases} already exist and point to a different "
                    f"vulnerability {vulnerability} than the requested "
                    f"vulnerability {vulnerability_id}."
                )
                return

    if vulnerability_id and not vulnerability:
        try:
            vulnerability = Vulnerability.objects.get(vulnerability_id=vulnerability_id)
        except Vulnerability.DoesNotExist:
            logger.error(f"Cannot get requested vulnerability {vulnerability_id}.")
            return
    if vulnerability:
        # TODO: We should keep multiple summaries, one for each advisory
        # if summary and summary != vulnerability.summary:
        #     logger.warning(
        #         f"Inconsistent summary for {vulnerability.vulnerability_id}. "
        #         f"Existing: {vulnerability.summary!r}, provided: {summary!r}"
        #     )
        associate_vulnerability_with_aliases(vulnerability=vulnerability, aliases=new_alias_names)
    else:
        try:
            vulnerability = create_vulnerability_and_add_aliases(
                aliases=new_alias_names, summary=summary
            )
            importer_name = get_importer_name(advisory)
            VulnerabilityChangeLog.log_import(
                importer=importer_name,
                source_url=advisory.url,
                vulnerability=vulnerability,
            )
        except Exception as e:
            logger.error(
                f"Cannot create vulnerability with summary {summary!r} and {new_alias_names!r} {e!r}.\n{traceback_format_exc()}."
            )
            return

    return vulnerability


def get_vulns_for_aliases_and_get_new_aliases(aliases):
    """
    Return ``new_aliases`` that are not in the database and
    ``existing_vulns`` that point to the given ``aliases``.
    """
    new_aliases = set(aliases)
    existing_vulns = set()
    for alias in Alias.objects.filter(alias__in=aliases):
        existing_vulns.add(alias.vulnerability)
        new_aliases.remove(alias.alias)
    return new_aliases, existing_vulns


@transaction.atomic
def create_vulnerability_and_add_aliases(aliases, summary):
    """
    Return a new ``vulnerability`` created with ``summary``
    and associate the ``vulnerability`` with ``aliases``.
    Raise exception if no alias is associated with the ``vulnerability``.
    """
    vulnerability = Vulnerability(summary=summary)
    vulnerability.save()
    associate_vulnerability_with_aliases(aliases, vulnerability)
    if not vulnerability.aliases.count():
        raise Exception(f"Vulnerability {vulnerability.vcid} must have one or more aliases")
    return vulnerability


def associate_vulnerability_with_aliases(aliases, vulnerability):
    for alias_name in aliases:
        alias = Alias(alias=alias_name, vulnerability=vulnerability)
        alias.save()
        logger.info(f"New alias for {vulnerability!r}: {alias_name}")
