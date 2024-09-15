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

from django.db import transaction

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.improver import MAX_CONFIDENCE
from vulnerabilities.models import Advisory
from vulnerabilities.models import Package
from vulnerabilities.models import PackageRelatedVulnerability
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import VulnerabilityRelatedReference
from vulnerabilities.models import VulnerabilitySeverity
from vulnerabilities.models import Weakness


def insert_advisory(advisory: AdvisoryData, pipeline_name: str, logger: Callable = None):
    obj = None
    try:
        obj, _ = Advisory.objects.get_or_create(
            aliases=advisory.aliases,
            summary=advisory.summary,
            affected_packages=[pkg.to_dict() for pkg in advisory.affected_packages],
            references=[ref.to_dict() for ref in advisory.references],
            date_published=advisory.date_published,
            weaknesses=advisory.weaknesses,
            url=advisory.url,
            defaults={
                "created_by": pipeline_name,
                "date_collected": datetime.now(timezone.utc),
            },
        )
    except Exception as e:
        if logger:
            logger(
                f"Error while processing {advisory!r} with aliases {advisory.aliases!r}: {e!r} \n {traceback_format_exc()}",
                level=logging.ERROR,
            )

    return obj


@transaction.atomic
def import_advisory(
    advisory: Advisory,
    pipeline_name: str,
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

    vulnerability = import_runner.get_or_create_vulnerability_and_aliases(
        vulnerability_id=None,
        aliases=advisory_data.aliases,
        summary=advisory_data.summary,
        advisory=advisory,
    )

    if not vulnerability:
        if logger:
            logger(f"Unable to get vulnerability for advisory: {advisory!r}", level=logging.WARNING)
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
            if not reference:
                continue

        VulnerabilityRelatedReference.objects.update_or_create(
            reference=reference,
            vulnerability=vulnerability,
        )
        for severity in ref.severities:
            try:
                published_at = str(severity.published_at) if severity.published_at else None
                _, created = VulnerabilitySeverity.objects.update_or_create(
                    scoring_system=severity.system.identifier,
                    reference=reference,
                    defaults={
                        "value": str(severity.value),
                        "scoring_elements": str(severity.scoring_elements),
                        "published_at": published_at,
                    },
                )
            except:
                if logger:
                    logger(
                        f"Failed to create VulnerabilitySeverity for: {severity} with error:\n{traceback_format_exc()}",
                        level=logging.ERROR,
                    )
            if not created:
                if logger:
                    logger(
                        f"Severity updated for reference {ref!r} to value: {severity.value!r} "
                        f"and scoring_elements: {severity.scoring_elements!r}",
                        level=logging.DEBUG,
                    )

    for affected_purl in affected_purls or []:
        vulnerable_package, _ = Package.objects.get_or_create_from_purl(purl=affected_purl)
        PackageRelatedVulnerability(
            vulnerability=vulnerability,
            package=vulnerable_package,
            created_by=pipeline_name,
            confidence=confidence,
            fix=False,
        ).update_or_create(advisory=advisory)

    for fixed_purl in fixed_purls:
        fixed_package, _ = Package.objects.get_or_create_from_purl(purl=fixed_purl)
        PackageRelatedVulnerability(
            vulnerability=vulnerability,
            package=fixed_package,
            created_by=pipeline_name,
            confidence=confidence,
            fix=True,
        ).update_or_create(advisory=advisory)

    if advisory_data.weaknesses and vulnerability:
        for cwe_id in advisory_data.weaknesses:
            cwe_obj, _ = Weakness.objects.get_or_create(cwe_id=cwe_id)
            cwe_obj.vulnerabilities.add(vulnerability)
            cwe_obj.save()

    advisory.date_imported = datetime.now(timezone.utc)
    advisory.save()
