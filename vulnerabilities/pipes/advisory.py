#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import hashlib
import logging
from datetime import datetime
from datetime import timezone
from traceback import format_exc as traceback_format_exc
from typing import Callable
from typing import List
from typing import Union

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Q
from django.db.models.query import QuerySet
from packageurl.contrib.purl2url import purl2url
from packageurl.contrib.url2purl import url2purl

from aboutcode.hashid import get_core_purl
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import PackageCommitPatchData
from vulnerabilities.importer import PatchData
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.improver import MAX_CONFIDENCE
from vulnerabilities.models import Advisory
from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import AdvisoryReference
from vulnerabilities.models import AdvisorySeverity
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import AdvisoryWeakness
from vulnerabilities.models import AffectedByPackageRelatedVulnerability
from vulnerabilities.models import Alias
from vulnerabilities.models import FixingPackageRelatedVulnerability
from vulnerabilities.models import Package
from vulnerabilities.models import PackageCommitPatch
from vulnerabilities.models import Patch
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import VulnerabilityRelatedReference
from vulnerabilities.models import VulnerabilitySeverity
from vulnerabilities.models import Weakness
from vulnerabilities.pipes.univers_utils import get_exact_purls_v2


def get_or_create_aliases(aliases: List) -> QuerySet:
    for alias in aliases:
        Alias.objects.get_or_create(alias=alias)
    return Alias.objects.filter(alias__in=aliases)


def get_or_create_advisory_aliases(aliases: List[str]) -> List[AdvisoryAlias]:
    existing = AdvisoryAlias.objects.filter(alias__in=aliases)
    existing_aliases = {a.alias for a in existing}

    to_create = [AdvisoryAlias(alias=alias) for alias in aliases if alias not in existing_aliases]
    AdvisoryAlias.objects.bulk_create(to_create, ignore_conflicts=True)

    return list(AdvisoryAlias.objects.filter(alias__in=aliases))


def get_or_create_advisory_references(references: List) -> List[AdvisoryReference]:
    reference_urls = [ref.url for ref in references]
    existing = AdvisoryReference.objects.filter(url__in=reference_urls)
    existing_urls = {r.url for r in existing}

    to_create = [
        AdvisoryReference(
            reference_id=ref.reference_id, url=ref.url, reference_type=ref.reference_type
        )
        for ref in references
        if ref.url not in existing_urls
    ]
    AdvisoryReference.objects.bulk_create(to_create, ignore_conflicts=True)

    return list(AdvisoryReference.objects.filter(url__in=reference_urls))


def get_or_create_advisory_severities(severities: List) -> QuerySet:
    severity_objs = []
    for severity in severities:
        published_at = str(severity.published_at) if severity.published_at else None
        if severity.scoring_elements or severity.value:
            sev, _ = AdvisorySeverity.objects.get_or_create(
                scoring_system=severity.system.identifier,
                value=severity.value,
                scoring_elements=severity.scoring_elements,
                defaults={
                    "published_at": published_at,
                },
                url=severity.url,
            )
            severity_objs.append(sev)
    return AdvisorySeverity.objects.filter(id__in=[severity.id for severity in severity_objs])


def get_or_create_advisory_weaknesses(weaknesses: List[str]) -> List[AdvisoryWeakness]:
    existing = AdvisoryWeakness.objects.filter(cwe_id__in=weaknesses)
    existing_ids = {w.cwe_id for w in existing}

    to_create = [AdvisoryWeakness(cwe_id=w) for w in weaknesses if w not in existing_ids]
    AdvisoryWeakness.objects.bulk_create(to_create, ignore_conflicts=True)

    return list(AdvisoryWeakness.objects.filter(cwe_id__in=weaknesses))


def get_or_create_advisory_package_commit_patches(
    commit_patches_data: List,
) -> List["PackageCommitPatch"]:
    if not commit_patches_data:
        return []

    data_map = {(c.commit_hash, c.vcs_url): c for c in commit_patches_data}
    pairs = list(data_map.keys())

    query = Q()
    for commit_hash, vcs_url in pairs:
        query |= Q(commit_hash=commit_hash, vcs_url=vcs_url)

    existing_commits_qs = PackageCommitPatch.objects.filter(query)
    existing_pairs = set(existing_commits_qs.values_list("commit_hash", "vcs_url"))

    to_update = []
    for commit_obj in existing_commits_qs:
        key = (commit_obj.commit_hash, commit_obj.vcs_url)
        input_data = data_map[key]

        if not commit_obj.patch_text and input_data.patch_text:
            commit_obj.patch_checksum = input_data.patch_checksum
            commit_obj.patch_text = input_data.patch_text
            to_update.append(commit_obj)
        elif (
            commit_obj.patch_text
            and input_data.patch_text
            and (commit_obj.patch_text != input_data.patch_text)
        ):
            raise ValidationError(
                f"Patch text conflict detected: existing record: {commit_obj.vcs_url} - {commit_obj.commit_hash} has different patch text"
                f"than {input_data.vcs_url} - {input_data.commit_hash}"
            )

    if to_update:
        PackageCommitPatch.objects.bulk_update(to_update, fields=["patch_checksum", "patch_text"])

    to_create = [
        PackageCommitPatch(
            commit_hash=c.commit_hash,
            vcs_url=c.vcs_url,
            patch_checksum=c.patch_checksum,
            patch_text=c.patch_text,
        )
        for c in commit_patches_data
        if (c.commit_hash, c.vcs_url) not in existing_pairs
    ]

    if to_create:
        PackageCommitPatch.objects.bulk_create(to_create)

    all_commits = PackageCommitPatch.objects.filter(query)
    return list(all_commits)


def get_or_create_advisory_patches(
    patches: List,
) -> List["Patch"]:
    if not patches:
        return []

    pairs = [(c.patch_text, c.patch_url) for c in patches]

    query = Q()
    for patch_text, patch_url in pairs:
        query |= Q(patch_text=patch_text, patch_url=patch_url)

    existing_commits_qs = Patch.objects.filter(query)
    existing_pairs = set(existing_commits_qs.values_list("patch_text", "patch_url"))

    to_create = [
        Patch(
            patch_url=getattr(c, "patch_url", None),
            patch_text=getattr(c, "patch_text", None),
            patch_checksum=getattr(c, "patch_checksum", None),
        )
        for c in patches
        if (c.patch_text, c.patch_url) not in existing_pairs
    ]

    if to_create:
        Patch.objects.bulk_create(to_create, ignore_conflicts=True)

    all_patches = Patch.objects.filter(query)
    return list(all_patches)


VCS_URLS_SUPPORTED_TYPES = {"github", "bitbucket", "gitlab"}


def classify_patch_source(url, commit_hash, patch_text):
    """
    Classify the patch type based on the given URL, commit hash, and patch text.
    Returns: a base_purl, patch_obj tuple where base_purl is a string PackageURL without version for supported VCS URLs, otherwise `None`.
    patch_obj is one of: (PackageCommitPatchData for supported VCS URLs with a commit,
    PatchData for raw patch text or non-VCS URLs, ReferenceV2 when unsupported VCS URL is paired with a commit hash)
    Returns `None` only when both `url` and `patch_text` are missing.
    """
    if not url:
        if not patch_text:
            return

        return None, [PatchData(patch_text=patch_text)]

    purl = url2purl(url)
    if not purl or (purl.type not in VCS_URLS_SUPPORTED_TYPES):
        if commit_hash:
            if not patch_text:
                return None, [
                    ReferenceV2(
                        reference_id=commit_hash, reference_type=AdvisoryReference.COMMIT, url=url
                    )
                ]

            return None, [
                ReferenceV2(
                    reference_id=commit_hash, reference_type=AdvisoryReference.COMMIT, url=url
                ),
                PatchData(patch_url=url, patch_text=patch_text),
            ]

        return None, [PatchData(patch_url=url, patch_text=patch_text)]

    if not commit_hash and not purl.version:
        return None, [PatchData(patch_url=url, patch_text=patch_text)]

    base_purl = get_core_purl(purl)
    base_purl_str = base_purl.to_string()
    base_url = purl2url(base_purl_str)
    package_commit_hash = purl.version or commit_hash
    return base_purl, [
        PackageCommitPatchData(
            vcs_url=base_url, commit_hash=package_commit_hash, patch_text=patch_text
        )
    ]


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
def insert_advisory_v2(
    advisory: AdvisoryData,
    pipeline_id: str,
    logger: Callable = None,
):
    from vulnerabilities.models import ImpactedPackage
    from vulnerabilities.models import PackageV2
    from vulnerabilities.utils import compute_content_id

    advisory_obj = None
    aliases = get_or_create_advisory_aliases(aliases=advisory.aliases)
    references = get_or_create_advisory_references(references=advisory.references_v2)
    severities = get_or_create_advisory_severities(severities=advisory.severities)
    patches = get_or_create_advisory_patches(patches=advisory.patches)
    weaknesses = get_or_create_advisory_weaknesses(weaknesses=advisory.weaknesses)
    content_id = compute_content_id(advisory_data=advisory)

    try:
        default_data = {
            "datasource_id": pipeline_id,
            "advisory_id": advisory.advisory_id,
            "avid": f"{pipeline_id}/{advisory.advisory_id}",
            "summary": advisory.summary,
            "date_published": advisory.date_published,
            "date_collected": datetime.now(timezone.utc),
            "original_advisory_text": advisory.original_advisory_text,
        }

        advisory_obj, created = AdvisoryV2.objects.get_or_create(
            unique_content_id=content_id,
            url=advisory.url,
            defaults=default_data,
        )
        related_fields = {
            "aliases": aliases,
            "references": references,
            "severities": severities,
            "weaknesses": weaknesses,
            "patches": patches,
        }

        for field_name, values in related_fields.items():
            if values:
                getattr(advisory_obj, field_name).add(*values)

    except AdvisoryV2.MultipleObjectsReturned:
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

    if created:
        for affected_pkg in advisory.affected_packages:
            impact = ImpactedPackage.objects.create(
                advisory=advisory_obj,
                base_purl=str(affected_pkg.package),
                affecting_vers=str(affected_pkg.affected_version_range)
                if affected_pkg.affected_version_range
                else None,
                fixed_vers=str(affected_pkg.fixed_version_range)
                if affected_pkg.fixed_version_range
                else None,
            )
            package_affected_purls, package_fixed_purls = get_exact_purls_v2(
                affected_package=affected_pkg,
                logger=logger,
            )
            affected_packages_v2 = [
                PackageV2.objects.get_or_create_from_purl(purl=purl)[0]
                for purl in package_affected_purls
            ]
            fixed_packages_v2 = [
                PackageV2.objects.get_or_create_from_purl(purl=purl)[0]
                for purl in package_fixed_purls
            ]
            impact.affecting_packages.add(*affected_packages_v2)
            impact.fixed_by_packages.add(*fixed_packages_v2)

            introduced_commit_v2 = get_or_create_advisory_package_commit_patches(
                affected_pkg.introduced_by_commit_patches
            )
            fixed_commit_v2 = get_or_create_advisory_package_commit_patches(
                affected_pkg.fixed_by_commit_patches
            )
            impact.introduced_by_package_commit_patches.add(*introduced_commit_v2)
            impact.fixed_by_package_commit_patches.add(*fixed_commit_v2)
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


def advisories_checksum(advisories: Union[Advisory, List[Advisory]]) -> str:
    if isinstance(advisories, Advisory) or isinstance(advisories, AdvisoryV2):
        advisories = [advisories]

    contents = sorted([advisory.unique_content_id for advisory in advisories])
    combined_contents = "".join(contents)

    checksum = hashlib.sha1(combined_contents.encode())
    return checksum.hexdigest()
