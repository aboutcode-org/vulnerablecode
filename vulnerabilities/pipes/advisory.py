#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from datetime import datetime
from datetime import timezone
from traceback import format_exc as traceback_format_exc
from typing import Callable
from typing import List

from django.db import transaction
from django.db.models.query import QuerySet

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.improver import MAX_CONFIDENCE
from vulnerabilities.models import Advisory
from vulnerabilities.models import AffectedByPackageRelatedVulnerability
from vulnerabilities.models import Alias
from vulnerabilities.models import FixingPackageRelatedVulnerability
from vulnerabilities.models import Package
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import VulnerabilityRelatedReference
from vulnerabilities.models import VulnerabilitySeverity
from vulnerabilities.models import Weakness


def get_or_create_aliases(aliases: List) -> QuerySet:
    for alias in aliases:
        Alias.objects.get_or_create(alias=alias)
    return Alias.objects.filter(alias__in=aliases)


def insert_advisory(advisory: AdvisoryData, pipeline_id: str, logger: Callable = None):
    from vulnerabilities.utils import compute_content_id

    advisory_obj = None
    aliases = get_or_create_aliases(aliases=advisory.aliases)
    content_id = compute_content_id(advisory_data=advisory)
    try:
        default_data = {
            "summary": advisory.summary,
            "affected_packages": [pkg.to_dict() for pkg in advisory.affected_packages],
            "references": [ref.to_dict() for ref in advisory.references],
            "date_published": advisory.date_published,
            "weaknesses": advisory.weaknesses,
            "created_by": pipeline_id,
            "date_collected": datetime.now(timezone.utc),
        }

        advisory_obj, _ = Advisory.objects.get_or_create(
            unique_content_id=content_id,
            url=advisory.url,
            defaults=default_data,
        )
        advisory_obj.aliases.add(*aliases)
    except Advisory.MultipleObjectsReturned:
        logger.error(
            f"Multiple Advisories returned: unique_content_id: {content_id}, url: {advisory.url}, advisory: {advisory!r}"
        )
        raise
    except Exception as e:
        if logger:
            logger(
                f"Error while processing {advisory!r} with aliases {advisory.aliases!r}: {e!r} \n {traceback_format_exc()}",
                level=logging.ERROR,
            )

    return advisory_obj


@transaction.atomic
def import_advisory(
    advisory: Advisory,
    pipeline_id: str,
    confidence: int = MAX_CONFIDENCE,
    logger: Callable = None,
):
    """
    Create initial Vulnerability Package relationships for the advisory,
    including references and severity scores.

    Package relationships are established only for resolved (concrete) versions.
    """
    from vulnerabilities import import_runner
    from vulnerabilities.improvers import default

    advisory_data: AdvisoryData = advisory.to_advisory_data()
    if logger:
        logger(f"Importing advisory id: {advisory.id}", level=logging.DEBUG)

    affected_purls = []
    fixed_purls = []
    for affected_package in advisory_data.affected_packages:
        package_affected_purls, package_fixed_purls = default.get_exact_purls(
            affected_package=affected_package
        )
        affected_purls.extend(package_affected_purls)
        fixed_purls.extend(package_fixed_purls)

    aliases = get_or_create_aliases(advisory_data.aliases)
    vulnerability = import_runner.get_or_create_vulnerability_and_aliases(
        vulnerability_id=None,
        aliases=aliases,
        summary=advisory_data.summary,
        advisory=advisory,
    )

    if not vulnerability:
        if logger:
            logger(f"Unable to get vulnerability for advisory: {advisory!r}", level=logging.ERROR)
        return

    for ref in advisory_data.references:
        reference = VulnerabilityReference.objects.get_or_none(
            reference_id=ref.reference_id,
            url=ref.url,
        )
        if not reference:
            reference = import_runner.create_valid_vulnerability_reference(
                reference_id=ref.reference_id,
                url=ref.url,
            )
        if reference:
            VulnerabilityRelatedReference.objects.update_or_create(
                reference=reference,
                vulnerability=vulnerability,
            )
        for severity in ref.severities:
            try:
                published_at = str(severity.published_at) if severity.published_at else None
                vulnerability_severity, created = VulnerabilitySeverity.objects.update_or_create(
                    scoring_system=severity.system.identifier,
                    url=ref.url,
                    value=severity.value,
                    scoring_elements=severity.scoring_elements,
                    defaults={
                        "published_at": published_at,
                    },
                )
                vulnerability.severities.add(vulnerability_severity)
                if not created and logger:
                    logger(
                        f"Severity updated for reference {ref.url!r} to value: {severity.value!r} "
                        f"and scoring_elements: {severity.scoring_elements!r}",
                        level=logging.DEBUG,
                    )
            except:
                if logger:
                    logger(
                        f"Failed to create VulnerabilitySeverity for: {severity} with error:\n{traceback_format_exc()}",
                        level=logging.ERROR,
                    )

    for affected_purl in affected_purls or []:
        vulnerable_package, _ = Package.objects.get_or_create_from_purl(purl=affected_purl)
        AffectedByPackageRelatedVulnerability(
            vulnerability=vulnerability,
            package=vulnerable_package,
            created_by=pipeline_id,
            confidence=confidence,
        ).update_or_create(advisory=advisory)

    for fixed_purl in fixed_purls:
        fixed_package, _ = Package.objects.get_or_create_from_purl(purl=fixed_purl)
        FixingPackageRelatedVulnerability(
            vulnerability=vulnerability,
            package=fixed_package,
            created_by=pipeline_id,
            confidence=confidence,
        ).update_or_create(advisory=advisory)

    if advisory_data.weaknesses and vulnerability:
        for cwe_id in advisory_data.weaknesses:
            cwe_obj, _ = Weakness.objects.get_or_create(cwe_id=cwe_id)
            cwe_obj.vulnerabilities.add(vulnerability)
            cwe_obj.save()

    advisory.date_imported = datetime.now(timezone.utc)
    advisory.save()
