# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import saneyaml
from django.db.models import Prefetch

from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import ImpactedPackage
from vulnerabilities.models import ImpactedPackageAffecting
from vulnerabilities.models import ImpactedPackageFixedBy
from vulnerabilities.models import PackageCommitPatch
from vulnerabilities.models import PackageV2


def package_prefetched_qs(checkpoint):
    count = None
    qs = (
        PackageV2.objects.order_by("type", "namespace", "name", "version")
        .only("package_url", "type", "namespace", "name", "version")
        .prefetch_related(
            Prefetch(
                "affected_in_impacts",
                queryset=ImpactedPackage.objects.only("advisory_id").prefetch_related(
                    Prefetch(
                        "advisory",
                        queryset=AdvisoryV2.objects.only("avid"),
                    )
                ),
            ),
            Prefetch(
                "fixed_in_impacts",
                queryset=ImpactedPackage.objects.only("advisory_id").prefetch_related(
                    Prefetch(
                        "advisory",
                        queryset=AdvisoryV2.objects.only("avid"),
                    )
                ),
            ),
        )
    )

    if checkpoint:
        affected_package_ids_qs = (
            ImpactedPackageAffecting.objects.filter(created_at__gte=checkpoint)
            .values_list("package_id", flat=True)
            .distinct()
        )
        fixing_package_ids_qs = (
            ImpactedPackageFixedBy.objects.filter(created_at__gte=checkpoint)
            .values_list("package_id", flat=True)
            .distinct()
        )

        updated_packages = affected_package_ids_qs.union(fixing_package_ids_qs)
        count = updated_packages.count()
        qs = qs.filter(id__in=updated_packages)

    count = qs.count() if not count else count

    return count, qs


def get_package_related_advisory(packages):
    package_vulnerabilities = []
    for package in packages:
        affected_by_vulnerabilities = [
            impact.advisory.avid for impact in package.affected_in_impacts.all()
        ]
        fixing_vulnerabilities = [impact.advisory.avid for impact in package.fixed_in_impacts.all()]

        package_vulnerability = {
            "purl": package.package_url,
            "affected_by_advisories": sorted(affected_by_vulnerabilities),
            "fixing_advisories": sorted(fixing_vulnerabilities),
        }
        package_vulnerabilities.append(package_vulnerability)

    return package.package_url, package_vulnerabilities


def advisory_prefetched_qs(checkpoint):
    qs = AdvisoryV2.objects.order_by("date_collected").prefetch_related(
        "impacted_packages",
        "aliases",
        "references",
        "severities",
        "weaknesses",
    )

    return qs.filter(date_collected__gte=checkpoint) if checkpoint else qs


def serialize_severity(sev):
    return {
        "score": sev.value,
        "scoring_system": sev.scoring_system,
        "scoring_elements": sev.scoring_elements,
        "published_at": str(sev.published_at),
        "url": sev.url,
    }


def serialize_references(reference):
    return {
        "url": reference.url,
        "reference_type": reference.reference_type,
        "reference_id": reference.reference_id,
    }


def serialize_advisory(advisory):
    """Return a plain data mapping serialized from advisory object."""
    aliases = sorted([a.alias for a in advisory.aliases.all()])
    severities = [serialize_severity(sev) for sev in advisory.severities.all()]
    weaknesses = [wkns.cwe for wkns in advisory.weaknesses.all()]
    references = [serialize_references(ref) for ref in advisory.references.all()]
    impacts = [
        {
            "purl": impact.base_purl,
            "affected_versions": impact.affecting_vers,
            "fixed_versions": impact.fixed_vers,
        }
        for impact in advisory.impacted_packages.all()
    ]

    return {
        "advisory_id": advisory.advisory_id,
        "datasource_id": advisory.avid,
        "datasource_url": advisory.url,
        "aliases": aliases,
        "summary": advisory.summary,
        "impacted_packages": impacts,
        "severities": severities,
        "weaknesses": weaknesses,
        "references": references,
    }


def write_file(repo_path, file_path, data):
    """Write ``data`` as YAML to ``repo_path``."""
    write_to = repo_path / file_path
    write_to.parent.mkdir(parents=True, exist_ok=True)
    with open(write_to, encoding="utf-8", mode="w") as f:
        f.write(saneyaml.dump(data))
