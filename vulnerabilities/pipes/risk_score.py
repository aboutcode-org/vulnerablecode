#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from decimal import ROUND_HALF_UP
from decimal import Decimal

from django.db.models import Max

from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import PackageV2


def quantize_1(value):
    if value is None:
        return None

    return Decimal(str(value)).quantize(
        Decimal("0.1"),
        rounding=ROUND_HALF_UP,
    )


def compute_package_risk_score(package, current_advisory_risk_score=None):
    """Calculate the risk score for a single PackageV2 object."""
    max_risk = (
        AdvisoryV2.objects.latest_affecting_advisories_for_purl(package.package_url)
        .aggregate(max_risk=Max("risk_score"))
        .get("max_risk")
    )
    # include current advisory risk score in the calculation if provided and is higher than the max risk score from the database
    if current_advisory_risk_score is not None:
        max_risk = max(max_risk or 0, current_advisory_risk_score)
    if max_risk is None:
        return None
    return round(float(max_risk), 1)


def compute_package_risk_score_bulk(packages):
    """Calculate the risk score for a single PackageV2 object."""
    purls = packages.values_list("package_url", flat=True)
    advisories = AdvisoryV2.objects.latest_affecting_advisories_for_purls(purls).only(
        "id", "risk_score"
    )
    qs = (
        PackageV2.objects.filter(
            id__in=packages.values_list("id", flat=True),
            affected_in_impacts__advisory__risk_score__isnull=False,
            affected_in_impacts__advisory__in=advisories,
        )
        .distinct()
        .annotate(computed_risk=Max("affected_in_impacts__advisory__risk_score"))
        .only("id")
    )

    batch = []
    batch_size = 5000
    updated = 0

    for pkg in qs.iterator(chunk_size=batch_size):
        pkg.risk_score = round(float(pkg.computed_risk), 1)
        batch.append(pkg)

        if len(batch) >= batch_size:
            updated += bulk_update(
                model=PackageV2,
                items=batch,
                fields=["risk_score"],
            )
            batch.clear()

    updated += bulk_update(
        model=PackageV2,
        items=batch,
        fields=["risk_score"],
    )


def compute_advisory_risk_score(advisory):
    """
    Calculate the risk score for a single AdvisoryV2 object.
    Returns a tuple of (weighted_severity, exploitability, risk_score).
    """
    from vulnerabilities.risk import compute_vulnerability_risk_factors

    weighted_severity = None
    exploitability = None
    risk_score = None

    references = advisory.references.all()
    exploits = advisory.exploits.all()

    severities = list(advisory.severities.all())

    for rel in advisory.related_advisory_severities.all():
        severities.extend(rel.severities.all())

    try:
        calculated_weighted_severity, calculated_exploitability = (
            compute_vulnerability_risk_factors(
                references=references,
                severities=severities,
                exploits=exploits,
            )
        )

        weighted_severity = calculated_weighted_severity
        exploitability = calculated_exploitability
        if exploitability and weighted_severity:
            risk_score = min(float(exploitability * weighted_severity), 10.0)
            risk_score = round(risk_score, 1)
    except Exception as e:
        risk_score = None

    return quantize_1(weighted_severity), quantize_1(exploitability), quantize_1(risk_score)


def bulk_update(model, items, fields, logger=None):
    item_count = 0
    if items:
        try:
            model.objects.bulk_update(objs=items, fields=fields)
            item_count += len(items)
        except Exception as e:
            if logger:
                logger(f"Error updating {model.__name__}: {e}")
        items.clear()
    return item_count
