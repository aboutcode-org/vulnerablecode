#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import datetime
import logging
from traceback import format_exc as traceback_format_exc
from typing import Iterable
from typing import List

from django.core.exceptions import ValidationError
from django.db import transaction

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.improver import Inference
from vulnerabilities.improvers.default import AdvisoryBasedDefaultImprover
from vulnerabilities.models import Advisory
from vulnerabilities.models import Alias
from vulnerabilities.models import Package
from vulnerabilities.models import PackageRelatedVulnerability
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import VulnerabilityRelatedReference
from vulnerabilities.models import VulnerabilitySeverity
from vulnerabilities.models import Weakness

logger = logging.getLogger(__name__)


class ImportRunner:
    """
    The ImportRunner is responsible for inserting and updating data about vulnerabilities and
    affected/unaffected/fixed packages in the database. The main goal for the implementation
    is correctness

    Correctness:
        - There must be no duplicates in the database (should be enforced by the schema).
        - No valid data from the data source must be skipped or truncated.
    """

    def __init__(self, importer_class: Importer):
        self.importer_class = importer_class

    def run(self) -> None:
        """
        Create a data source for the given importer and store the data retrieved in the database.
        """
        importer_name = self.importer_class.qualified_name
        importer_class = self.importer_class
        logger.info(f"Starting import for {importer_name}")
        advisory_datas = importer_class().advisory_data()
        count = self.process_advisories(advisory_datas=advisory_datas, importer_name=importer_name)
        logger.info(f"Finished import for {importer_name}. Imported {count} advisories.")

    def do_import(self, advisories) -> None:
        improver = AdvisoryBasedDefaultImprover(advisories=advisories)
        logger.info(f"Running improver: {improver.qualified_name}")
        improver_name = improver.qualified_name
        advisories = []
        for advisory in improver.interesting_advisories:
            if advisory.date_imported:
                continue
            logger.info(f"Processing advisory: {advisory!r}")
            try:
                inferences = improver.get_inferences(advisory_data=advisory.to_advisory_data())
                process_inferences(
                    inferences=inferences,
                    advisory=advisory,
                    improver_name=improver_name,
                )
            except Exception as e:
                logger.info(f"Failed to process advisory: {advisory!r} with error {e!r}")
        logger.info("Finished improving using %s.", improver.__class__.qualified_name)

    def process_advisories(
        self, advisory_datas: Iterable[AdvisoryData], importer_name: str
    ) -> List:
        """
        Insert advisories into the database
        Return the number of inserted advisories.
        """
        count = 0
        advisories = []
        for data in advisory_datas:
            # https://nvd.nist.gov/vuln/detail/CVE-2013-4314
            # https://github.com/cms-dev/cms/issues/888#issuecomment-516977572
            try:
                obj, created = Advisory.objects.get_or_create(
                    aliases=data.aliases,
                    summary=data.summary,
                    affected_packages=[pkg.to_dict() for pkg in data.affected_packages],
                    references=[ref.to_dict() for ref in data.references],
                    date_published=data.date_published,
                    weaknesses=data.weaknesses,
                    defaults={
                        "created_by": importer_name,
                        "date_collected": datetime.datetime.now(tz=datetime.timezone.utc),
                    },
                )
                if not obj.date_imported:
                    advisories.append(obj)
            except Exception as e:
                logger.error(
                    f"Error while processing {data!r} with aliases {data.aliases!r}: {e!r} \n {traceback_format_exc()}"
                )
                continue
            if created:
                logger.info(
                    f"[*] New Advisory with aliases: {obj.aliases!r}, created_by: {obj.created_by}"
                )
                count += 1
            else:
                logger.debug(f"Advisory with aliases: {obj.aliases!r} already exists.")
        try:
            self.do_import(advisories)
        except Exception as e:
            logger.error(
                f"Error while processing advisories from {importer_name!r}: {e!r} \n {traceback_format_exc()}"
            )
        return count


@transaction.atomic
def process_inferences(inferences: List[Inference], advisory: Advisory, improver_name: str):
    """
    Return number of inferences processed.
    An atomic transaction that updates both the Advisory (e.g. date_improved)
    and processes the given inferences to create or update corresponding
    database fields.

    This avoids failing the entire improver when only a single inference is
    erroneous. Also, the atomic transaction for every advisory and its
    inferences makes sure that date_improved of advisory is consistent.
    """
    inferences_processed_count = 0

    if not inferences:
        logger.warning(f"Nothing to improve. Source: {improver_name} Advisory id: {advisory.id}")
        return inferences_processed_count

    logger.info(f"Improving advisory id: {advisory.id}")

    for inference in inferences:
        vulnerability = get_or_create_vulnerability_and_aliases(
            vulnerability_id=inference.vulnerability_id,
            alias_names=inference.aliases,
            summary=inference.summary,
        )

        if not vulnerability:
            logger.warning(f"Unable to get vulnerability for inference: {inference!r}")
            continue

        for ref in inference.references:

            reference = VulnerabilityReference.objects.get_or_none(
                reference_id=ref.reference_id,
                url=ref.url,
            )

            if not reference:
                reference = create_valid_vulnerability_reference(
                    reference_id=ref.reference_id,
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
            vulnerable_package = Package.objects.get_or_create_from_purl(purl=affected_purl)
            PackageRelatedVulnerability(
                vulnerability=vulnerability,
                package=vulnerable_package,
                created_by=improver_name,
                confidence=inference.confidence,
                fix=False,
            ).update_or_create()

        if inference.fixed_purl:
            fixed_package = Package.objects.get_or_create_from_purl(purl=inference.fixed_purl)
            PackageRelatedVulnerability(
                vulnerability=vulnerability,
                package=fixed_package,
                created_by=improver_name,
                confidence=inference.confidence,
                fix=True,
            ).update_or_create()

        if inference.weaknesses and vulnerability:
            for cwe_id in inference.weaknesses:
                cwe_obj, created = Weakness.objects.get_or_create(cwe_id=cwe_id)
                cwe_obj.vulnerabilities.add(vulnerability)
                cwe_obj.save()
        inferences_processed_count += 1

    advisory.date_imported = datetime.datetime.now(tz=datetime.timezone.utc)
    advisory.save()
    return inferences_processed_count


def create_valid_vulnerability_reference(url, reference_id=None):
    """
    Create and return a new validated VulnerabilityReference from a
    ``url`` and ``reference_id``.
    Return None and log a warning if this is not a valid reference.
    """
    reference = VulnerabilityReference(
        reference_id=reference_id,
        url=url,
    )

    try:
        reference.full_clean()
    except ValidationError as e:
        logger.warning(f"Invalid vulnerability reference: {reference!r}: {e}")
        return

    reference.save()
    return reference


def get_or_create_vulnerability_and_aliases(alias_names, vulnerability_id=None, summary=None):
    """
    Get or create vulnerabilitiy and aliases such that all existing and new
    aliases point to the same vulnerability
    """
    existing_vulns = set()
    alias_names = set(alias_names)
    new_alias_names = set()
    for alias_name in alias_names:
        try:
            alias = Alias.objects.get(alias=alias_name)
            existing_vulns.add(alias.vulnerability)
        except Alias.DoesNotExist:
            new_alias_names.add(alias_name)

    # If given set of aliases point to different vulnerabilities in the
    # database, request is malformed
    # TODO: It is possible that all those vulnerabilities are actually
    # the same at data level, figure out a way to merge them
    if len(existing_vulns) > 1:
        logger.warning(
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
        logger.warning(
            f"Given aliases {alias_names!r} already exist and point to existing"
            f"vulnerability {existing_alias_vuln}. Unable to create Vulnerability "
            f"with vulnerability_id {vulnerability_id}. Skipped"
        )
        return

    if existing_alias_vuln:
        vulnerability = existing_alias_vuln
    elif vulnerability_id:
        try:
            vulnerability = Vulnerability.objects.get(vulnerability_id=vulnerability_id)
        except Vulnerability.DoesNotExist:
            logger.warning(
                f"Given vulnerability_id: {vulnerability_id} does not exist in the database"
            )
            return
    else:
        vulnerability = Vulnerability(summary=summary)
        vulnerability.save()

    if summary and summary != vulnerability.summary:
        logger.warning(
            f"Inconsistent summary for {vulnerability!r}. "
            f"Existing: {vulnerability.summary}, provided: {summary}"
        )

    for alias_name in new_alias_names:
        alias = Alias(alias=alias_name, vulnerability=vulnerability)
        alias.save()
        logger.info(f"New alias for {vulnerability!r}: {alias_name}")

    return vulnerability
