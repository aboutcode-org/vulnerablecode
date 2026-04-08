#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from datetime import timedelta
from traceback import format_exc as traceback_format_exc

from aboutcode.pipeline import LoopProgress
from django.db.models import F
from django.db.models import Q
from django.utils import timezone
from fetchcode.package_versions import SUPPORTED_ECOSYSTEMS as FETCHCODE_SUPPORTED_ECOSYSTEMS
from packageurl import PackageURL
from univers.version_range import RANGE_CLASS_BY_SCHEMES
from univers.version_range import VersionRange

from vulnerabilities.models import ImpactedPackage
from vulnerabilities.models import ImpactedPackageAffecting
from vulnerabilities.models import PackageV2
from vulnerabilities.models import PipelineSchedule
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.pipes.fetchcode_utils import get_versions
from vulnerabilities.utils import update_purl_version


class UnfurlVersionRangePipeline(VulnerableCodePipeline):
    """
    Unfurl affected version ranges by first processing those that have
    never been unfurled and then handling ranges that were last unfurled
    two or more days ago.
    """

    pipeline_id = "unfurl_version_range_v2"

    run_interval = 2
    run_priority = PipelineSchedule.ExecutionPriority.HIGH

    # Days elapsed before version range is re-unfurled
    reunfurl_after_days = 2

    @classmethod
    def steps(cls):
        return (cls.unfurl_version_range,)

    def unfurl_version_range(self):
        processed_impacted_packages_count = 0
        processed_affected_packages_count = 0
        cached_versions = {}
        update_unfurl_date = []
        update_successful_unfurl_date = []
        update_batch_size = 5000
        chunk_size = 5000

        impacted_packages = impacted_package_qs(cutoff_day=self.reunfurl_after_days)
        impacted_packages_count = impacted_packages.count()
        self.log(f"Unfurl affected vers range for {impacted_packages_count:,d} ImpactedPackage.")

        progress = LoopProgress(
            total_iterations=impacted_packages_count, progress_step=5, logger=self.log
        )
        for impact in progress.iter(impacted_packages.iterator(chunk_size=chunk_size)):
            update_unfurl_date.append(impact.pk)
            purl = PackageURL.from_string(impact.base_purl)
            if not impact.affecting_vers or not any(
                c in impact.affecting_vers for c in ("<", ">", "!")
            ):
                update_successful_unfurl_date.append(impact.pk)
                continue
            if purl.type not in FETCHCODE_SUPPORTED_ECOSYSTEMS:
                continue
            if purl.type not in RANGE_CLASS_BY_SCHEMES:
                continue

            versions = get_purl_versions(purl, cached_versions, self.log) or []
            affected_purls = get_affected_purls(
                versions=versions,
                impact=impact,
                logger=self.log,
            )
            if not affected_purls:
                continue

            processed_affected_packages_count += bulk_create_with_m2m(
                purls=affected_purls,
                impact=impact,
                relation=ImpactedPackageAffecting,
                logger=self.log,
            )
            update_successful_unfurl_date.append(impact.pk)
            processed_impacted_packages_count += 1

            if len(update_unfurl_date) > update_batch_size:
                ImpactedPackage.objects.filter(pk__in=update_unfurl_date).update(
                    last_range_unfurl_at=timezone.now()
                )
                ImpactedPackage.objects.filter(pk__in=update_successful_unfurl_date).update(
                    last_successful_range_unfurl_at=timezone.now()
                )
                update_unfurl_date.clear()
                update_successful_unfurl_date.clear()

        ImpactedPackage.objects.filter(pk__in=update_unfurl_date).update(
            last_range_unfurl_at=timezone.now()
        )
        ImpactedPackage.objects.filter(pk__in=update_successful_unfurl_date).update(
            last_successful_range_unfurl_at=timezone.now()
        )
        self.log(f"Successfully processed {processed_impacted_packages_count:,d} ImpactedPackage.")
        self.log(f"{processed_affected_packages_count:,d} new Impact-Package relation created.")


def get_affected_purls(versions, impact, logger):
    affecting_version_range = VersionRange.from_string(impact.affecting_vers)
    version_class = affecting_version_range.version_class

    try:
        if not versions:
            return []
        versions = [version_class(v) for v in versions]
    except Exception as e:
        logger(
            f"Error while parsing versions for {impact.base_purl!s}: {e!r} \n {traceback_format_exc()}",
            level=logging.ERROR,
        )
        return

    affected_purls = []
    for version in versions:
        try:
            if version in affecting_version_range:
                affected_purls.append(
                    update_purl_version(
                        purl=impact.base_purl,
                        version=str(version),
                    )
                )
        except Exception as e:
            logger(
                (
                    f"Error while checking {version!s} in {affecting_version_range!s} for "
                    f"advisory {impact.advisory.avid}: {e!r} \n {traceback_format_exc()}"
                ),
                level=logging.ERROR,
            )
    return affected_purls


def get_purl_versions(purl, cached_versions, logger):
    if not purl in cached_versions:
        purls = get_versions(purl, logger)
        if purls is not None:
            cached_versions[purl] = purls
    return cached_versions.get(purl) or []


def bulk_create_with_m2m(purls, impact, relation, logger):
    """Bulk create PackageV2 and also bulk populate M2M Impact and Package relationships."""
    if not purls:
        return 0

    affected_packages_v2 = PackageV2.objects.bulk_get_or_create_from_purls(purls=purls)

    affected_packages_v2[-1].calculate_version_rank

    relations = [
        relation(impacted_package=impact, package=package) for package in affected_packages_v2
    ]

    try:
        relation.objects.bulk_create(relations, ignore_conflicts=True)
    except Exception as e:
        logger(f"Error creating ImpactedPackage {relation}: {e!r} \n {traceback_format_exc()}")
        return 0

    return len(relations)


def impacted_package_qs(cutoff_day=2):
    cutoff = timezone.now() - timedelta(days=cutoff_day)
    return (
        ImpactedPackage.objects.filter(
            (Q(last_range_unfurl_at__isnull=True) | Q(last_range_unfurl_at__lte=cutoff))
            & Q(affecting_vers__isnull=False)
            & ~Q(affecting_vers="")
        )
        .order_by(F("last_range_unfurl_at").asc(nulls_first=True))
        .only("pk", "affecting_vers", "advisory", "base_purl")
    )
