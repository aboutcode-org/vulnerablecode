#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django.db import migrations

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import PatchData
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.utils import compute_content_id_v2
from vulnerabilities.utils import normalize_list
from vulnerabilities.utils import purl_to_dict

"""
Drop legacy OSVDB-derived aliases imported from rubygem data sources.

The rubysec advisory data contains legacy references to the defunct OSVDB
database in its `osvdb` field, and these were imported as `OSV-<number>`
aliases. These are not public aliases and collide with the modern OSV.dev
namespace. Genuine OSV.dev identifiers have the form `OSV-<year>-<number>`
and are preserved.

See https://github.com/aboutcode-org/vulnerablecode/issues/2421
"""

OSVDB_DERIVED_ALIAS_REGEX = r"^OSV-\d+$"


def commit_patch_to_dict(patch):
    return {
        "vcs_url": patch.vcs_url,
        "commit_hash": patch.commit_hash,
        "patch_text": patch.patch_text,
        "patch_checksum": patch.patch_checksum,
    }


def to_affected_package_data(impact):
    """Return `AffectedPackageV2` data from the impact."""
    return AffectedPackageV2.from_dict(
        {
            "package": purl_to_dict(impact.base_purl),
            "affected_version_range": impact.affecting_vers,
            "fixed_version_range": impact.fixed_vers,
            "introduced_by_commit_patches": [
                commit_patch_to_dict(commit)
                for commit in impact.introduced_by_package_commit_patches.all()
            ],
            "fixed_by_commit_patches": [
                commit_patch_to_dict(commit)
                for commit in impact.fixed_by_package_commit_patches.all()
            ],
        }
    )


def to_patch_data(patch):
    """Return `PatchData` from the Patch."""
    return PatchData.from_dict(
        {
            "patch_url": patch.patch_url,
            "patch_text": patch.patch_text,
            "patch_checksum": patch.patch_checksum,
        }
    )


def to_reference_v2_data(ref):
    return ReferenceV2.from_dict(
        {
            "reference_id": ref.reference_id,
            "reference_type": ref.reference_type,
            "url": ref.url,
        }
    )


def to_vulnerability_severity_data(severity):
    return VulnerabilitySeverity.from_dict(
        {
            "system": severity.scoring_system,
            "value": severity.value,
            "scoring_elements": severity.scoring_elements,
            "published_at": severity.published_at,
            "url": severity.url,
        }
    )


def to_advisory_data(advisory):
    return AdvisoryDataV2(
        advisory_id=advisory.advisory_id,
        aliases=normalize_list([item.alias for item in advisory.aliases.all()]),
        summary=advisory.summary,
        affected_packages=normalize_list(
            [to_affected_package_data(impacted) for impacted in advisory.impacted_packages.all()]
        ),
        references=normalize_list([to_reference_v2_data(ref) for ref in advisory.references.all()]),
        patches=normalize_list([to_patch_data(patch) for patch in advisory.patches.all()]),
        date_published=advisory.date_published,
        weaknesses=normalize_list([weak.cwe_id for weak in advisory.weaknesses.all()]),
        severities=normalize_list(
            [to_vulnerability_severity_data(sev) for sev in advisory.severities.all()]
        ),
        url=advisory.url,
    )


def drop_osv_aliases(apps, schema_editor):
    AdvisoryAlias = apps.get_model("vulnerabilities", "AdvisoryAlias")
    AdvisoryV2 = apps.get_model("vulnerabilities", "AdvisoryV2")
    Alias = apps.get_model("vulnerabilities", "Alias")

    # Identify affected advisories before deleting associations
    advisory_ids = list(
        AdvisoryV2.objects.filter(aliases__alias__iregex=OSVDB_DERIVED_ALIAS_REGEX)
        .distinct()
        .values_list("id", flat=True)
    )

    # Delete legacy OSV- (OSVDB-derived) aliases
    AdvisoryAlias.objects.filter(alias__iregex=OSVDB_DERIVED_ALIAS_REGEX).delete()
    Alias.objects.filter(alias__iregex=OSVDB_DERIVED_ALIAS_REGEX).delete()

    # Recompute unique_content_id for affected advisories
    batch = []
    batch_size = 2000
    for advisory in AdvisoryV2.objects.filter(id__in=advisory_ids).iterator(chunk_size=1000):
        advisory.unique_content_id = compute_content_id_v2(to_advisory_data(advisory))
        batch.append(advisory)
        if len(batch) >= batch_size:
            AdvisoryV2.objects.bulk_update(batch, ["unique_content_id"])
            batch.clear()
    if batch:
        AdvisoryV2.objects.bulk_update(batch, ["unique_content_id"])


class Migration(migrations.Migration):

    dependencies = [
        ("vulnerabilities", "0142_advisoryv2_is_curation_advisoryv2_resolves_todos"),
    ]

    operations = [
        migrations.RunPython(
            drop_osv_aliases,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
