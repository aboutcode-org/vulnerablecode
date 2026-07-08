#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from collections import defaultdict
from datetime import timedelta

from django.db import transaction
from django.db.models import Exists
from django.db.models import Min
from django.db.models import OuterRef
from django.db.models import Q
from django.utils import timezone

from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import ImpactedPackage
from vulnerabilities.models import ImpactedPackageAffecting
from vulnerabilities.models import ImpactedPackageFixedBy
from vulnerabilities.models import PackageV2
from vulnerabilities.models import PipelineSchedule
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.pipes.group_advisories import group_single_package_with_provided_advisories
from vulnerabilities.pipes.risk_score import compute_package_risk_score_bulk
from vulnerabilities.utils import TYPES_WITH_MULTIPLE_IMPORTERS


class MarkUnfurlVersionRangePipeline(VulnerableCodePipeline):
    """
    Mark advisories as unfurled whose all impacts have been unfurled
    """

    pipeline_id = "mark_unfurl_version_range_v2"

    # Run pipeline every 10 minutes.
    run_interval = 10
    run_priority = PipelineSchedule.ExecutionPriority.HIGH

    @classmethod
    def steps(cls):
        return (cls.mark_all_impacts_unfurled,)

    def mark_all_impacts_unfurled(self):
        impacted_packages = ImpactedPackage.objects.all()
        advisories_qs = latest_advisories_with_all_impacts_unfurled_attempted(
            impacted_packages=impacted_packages
        )

        batch_size = 1000
        batch = []

        successful_qs = latest_advisories_with_all_impacts_unfurled_successfully(
            impacted_packages=impacted_packages,
        )

        for advisory_id in list(advisories_qs):
            batch.append(advisory_id)

            if len(batch) >= batch_size:
                successful_ids = set(successful_qs.filter(id__in=list(batch)))

                complete_advisories_import(
                    advisory_ids=list(batch), successful_advisory_ids=successful_ids
                )
                batch.clear()

        if batch:
            successful_ids = set(successful_qs.filter(id__in=list(batch)))

            complete_advisories_import(
                advisory_ids=list(batch), successful_advisory_ids=successful_ids
            )


def latest_advisories_with_all_impacts_unfurled_successfully(
    impacted_packages=None,
):
    unsuccessful_impacts = impacted_packages.filter(
        advisory_id=OuterRef("pk"),
        advisory__is_latest=True,
    ).filter(Q(last_range_unfurl_at__isnull=True) | Q(last_successful_range_unfurl_at__isnull=True))

    return (
        AdvisoryV2.objects.filter(
            _all_impacts_unfurled_successfully_at__isnull=True,
            is_latest=True,
        )
        .annotate(has_unsuccessful_impacts=Exists(unsuccessful_impacts))
        .filter(has_unsuccessful_impacts=False)
        .order_by("id")
        .values_list("id", flat=True)
    )


def latest_advisories_with_all_impacts_unfurled_attempted(
    impacted_packages=None,
):
    impacts_not_attempted = impacted_packages.filter(
        advisory_id=OuterRef("pk"),
        advisory__is_latest=True,
        last_range_unfurl_at__isnull=True,
    )

    cutoff = timezone.now() - timedelta(days=30)

    advisories = (
        AdvisoryV2.objects.filter(
            _all_impacts_unfurled_successfully_at__isnull=True,
            is_latest=True,
        )
        .filter(Q(_all_impacts_unfurled_at__isnull=True) | Q(_all_impacts_unfurled_at__lt=cutoff))
        .annotate(
            has_unattempted_impacts=Exists(impacts_not_attempted),
            first_base_purl=Min("impacted_packages__base_purl"),
        )
        .filter(has_unattempted_impacts=False)
        .order_by("_all_impacts_unfurled_at", "first_base_purl")
        .values_list("id", flat=True)
    )
    return advisories


@transaction.atomic
def complete_advisories_import(advisory_ids, successful_advisory_ids=[]):
    if not advisory_ids:
        return

    cur = timezone.now()

    AdvisoryV2.objects.filter(id__in=advisory_ids).update(_all_impacts_unfurled_at=cur)

    if successful_advisory_ids:
        AdvisoryV2.objects.filter(
            id__in=successful_advisory_ids,
        ).update(
            _all_impacts_unfurled_successfully_at=cur,
        )

    affecting_package_ids = set(
        ImpactedPackageAffecting.objects.filter(
            impacted_package__advisory_id__in=advisory_ids
        ).values_list(
            "package_id",
            flat=True,
        )
    )

    fixed_by_package_ids = set(
        ImpactedPackageFixedBy.objects.filter(
            impacted_package__advisory_id__in=advisory_ids
        ).values_list(
            "package_id",
            flat=True,
        )
    )

    compute_package_risk_score_bulk(PackageV2.objects.filter(id__in=affecting_package_ids))

    group_package_ids = affecting_package_ids | fixed_by_package_ids

    packages = PackageV2.objects.filter(
        id__in=group_package_ids, type__in=TYPES_WITH_MULTIPLE_IMPORTERS
    ).only("package_url", "id")

    group_advisories_for_packages_bulk_marking(packages)


def group_advisories_for_packages_bulk_marking(packages):
    purls = [package.package_url for package in packages]

    affecting_pairs = AdvisoryV2.objects.latest_affecting_advisory_purls_pairs(purls)

    fixed_pairs = AdvisoryV2.objects.latest_fixed_by_advisory_purls_pairs(purls)

    affecting_ids = {adv_id for _, adv_id in affecting_pairs}
    fixed_ids = {adv_id for _, adv_id in fixed_pairs}

    all_adv_ids = affecting_ids | fixed_ids

    advisories = AdvisoryV2.objects.filter(id__in=all_adv_ids).prefetch_related(
        "aliases",
        "impacted_packages__affecting_packages",
        "impacted_packages__fixed_by_packages",
    )

    advisory_map = {a.id: a for a in advisories}

    affecting_by_purl = defaultdict(list)

    for purl, advisory_id in affecting_pairs:
        affecting_by_purl[purl].append(advisory_map[advisory_id])

    fixed_by_purl = defaultdict(list)

    for purl, advisory_id in fixed_pairs:
        fixed_by_purl[purl].append(advisory_map[advisory_id])

    for package in packages:
        group_single_package_with_provided_advisories(
            package=package,
            affecting_advisories=affecting_by_purl.get(package.purl, []),
            fixed_by_advisories=fixed_by_purl.get(package.purl, []),
        )
