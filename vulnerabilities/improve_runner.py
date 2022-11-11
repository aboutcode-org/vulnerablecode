#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from datetime import datetime
from datetime import timezone
from typing import List

from django.core.exceptions import ValidationError
from django.db import transaction

from vulnerabilities.improver import Inference
from vulnerabilities.models import Advisory
from vulnerabilities.models import Alias
from vulnerabilities.models import Package
from vulnerabilities.models import PackageRelatedVulnerability
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import VulnerabilityRelatedReference
from vulnerabilities.models import VulnerabilitySeverity

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
            inferences = improver.get_inferences(advisory_data=advisory.to_advisory_data())
            process_inferences(
                inferences=inferences, advisory=advisory, improver_name=improver.qualified_name
            )
        logger.info("Finished improving using %s.", self.improver_class.qualified_name)


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
        if not inference.aliases:
            vulnerability = get_or_create_vulnerability_without_aliases(inference)
        else:
            vulnerability = get_or_create_vulnerability_and_aliases(
                vulnerability_id=inference.vulnerability_id,
                alias_names=inference.aliases,
                summary=inference.summary,
            )

        if not vulnerability:
            logger.warn(f"Unable to get vulnerability for inference: {inference!r}")
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
                    defaults={"value": str(severity.value)},
                )
                if updated:
                    logger.info(f"Severity updated for reference {ref!r} to {severity.value!r}")

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

    advisory.date_improved = datetime.now(timezone.utc)
    advisory.save()


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
            alias = Alias.objects.get(alias=alias_name)
            existing_vulns.add(alias.vulnerability)
        except Alias.DoesNotExist:
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
            vulnerability = Vulnerability.objects.get(vulnerability_id=vulnerability_id)
        except Vulnerability.DoesNotExist:
            logger.warn(
                f"Given vulnerability_id: {vulnerability_id} does not exist in the database"
            )
            return
    else:
        vulnerability = Vulnerability(summary=summary)
        vulnerability.save()

    if summary and summary != vulnerability.summary:
        logger.warn(
            f"Inconsistent summary for {vulnerability!r}. "
            f"Existing: {vulnerability.summary}, provided: {summary}"
        )

    for alias_name in new_alias_names:
        alias = Alias(alias=alias_name, vulnerability=vulnerability)
        alias.save()
        logger.info(f"New alias for {vulnerability!r}: {alias_name}")

    return vulnerability


def get_or_create_vulnerability_without_aliases(inference):
    """
    Get or create vulnerabilitiy without aliases

    Try to get vulnerability by matching references,
    summary and packages. If no vulnerability is found,
    create a new one.
    """

    refs_are_exact_match = True

    vuln_by_refs = {}

    ref_urls = [ref.url for ref in inference.references]

    references = VulnerabilityReference.objects.filter(url__in=ref_urls)

    if references.count() != len(ref_urls):
        refs_are_exact_match = False
    else:
        for ref in references:
            # saving it as a set to use intersection later
            vuln_by_refs[ref.url] = set(ref.vulnerabilities.all())

    if refs_are_exact_match:

        list_of_vulns_by_each_ref = vuln_by_refs.values()

        # Find all common vulnerabilities amongst all references
        common_vulns_in_refs = set.intersection(*list_of_vulns_by_each_ref)

        # For a single common vulnerability that have same exact reference
        # return it
        if len(common_vulns_in_refs) == 1:
            return common_vulns_in_refs.pop()

        # If there are multiple common vulnerabilities, try to find
        # one that matches the summary and packages
        elif len(common_vulns_in_refs) > 1:
            for vuln in common_vulns_in_refs:
                if vuln.summary == inference.summary:
                    if match_packages(inference, vuln):
                        return vuln

        else:
            # If there are no common vulnerabilities, fall back to creating
            # a new vulnerability
            pass

    # This is fallback for cases when we cannot find vulnerability
    # by references, summary and packages
    vulnerability = Vulnerability(summary=inference.summary)
    vulnerability.save()

    return vulnerability


def match_packages(inference, vuln):
    """
    Check if the packages in the inference match the packages in the vulnerability
    """
    for affected_purl in inference.affected_purls:
        if not find_package_and_check_related_to_vuln(purl=affected_purl, fix=False, vuln=vuln):
            return False
    if inference.fixed_purl and not find_package_and_check_related_to_vuln(
        purl=inference.fixed_purl, fix=True, vuln=vuln
    ):
        return False
    return True


def find_package_and_check_related_to_vuln(purl, fix, vuln):
    """
    Find package in the database and check if it is associated
    with the vulnerability.
    If package is not found, return False
    If package is found, but not associated with the vulnerability, return False
    If package is found and associated with the vulnerability, return True
    """
    try:
        package = Package.objects.for_purl(purl=purl)
        if not PackageRelatedVulnerability.objects.exists(
            vulnerability=vuln,
            package=package,
            fix=fix,
        ):
            return False
    except Package.DoesNotExist:
        return False
    return True
