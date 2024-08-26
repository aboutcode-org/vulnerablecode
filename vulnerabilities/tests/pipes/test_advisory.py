#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import pytest
from django.utils import timezone
from packageurl import PackageURL
from univers.version_range import VersionRange

from vulnerabilities import models
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.pipes.advisory import import_advisory

advisory_data1 = AdvisoryData(
    aliases=["CVE-2020-13371337"],
    summary="vulnerability description here",
    affected_packages=[
        AffectedPackage(
            package=PackageURL(type="pypi", name="dummy"),
            affected_version_range=VersionRange.from_string("vers:pypi/>=1.0.0|<=2.0.0"),
        )
    ],
    references=[Reference(url="https://example.com/with/more/info/CVE-2020-13371337")],
    date_published=timezone.now(),
    url="https://test.com",
)


def get_advisory1(created_by="test_pipeline"):
    return models.Advisory.objects.create(
        aliases=advisory_data1.aliases,
        summary=advisory_data1.summary,
        affected_packages=[pkg.to_dict() for pkg in advisory_data1.affected_packages],
        references=[ref.to_dict() for ref in advisory_data1.references],
        url=advisory_data1.url,
        created_by=created_by,
        date_collected=timezone.now(),
    )


def get_all_vulnerability_relationships_objects():
    return {
        "vulnerabilities": list(models.Vulnerability.objects.all()),
        "aliases": list(models.Alias.objects.all()),
        "references": list(models.VulnerabilityReference.objects.all()),
        "advisories": list(models.Advisory.objects.all()),
        "packages": list(models.Package.objects.all()),
        "references": list(models.VulnerabilityReference.objects.all()),
        "severity": list(models.VulnerabilitySeverity.objects.all()),
    }


@pytest.mark.django_db
def test_vulnerability_pipes_importer_import_advisory():
    advisory1 = get_advisory1(created_by="test_importer_pipeline")
    import_advisory(advisory=advisory1, pipeline_name="test_importer_pipeline")
    all_vulnerability_relation_objects = get_all_vulnerability_relationships_objects()
    import_advisory(advisory=advisory1, pipeline_name="test_importer_pipeline")
    assert all_vulnerability_relation_objects == get_all_vulnerability_relationships_objects()


@pytest.mark.django_db
def test_vulnerability_pipes_importer_import_advisory_different_pipelines():
    advisory1 = get_advisory1(created_by="test_importer_pipeline")
    import_advisory(advisory=advisory1, pipeline_name="test_importer1_pipeline")
    all_vulnerability_relation_objects = get_all_vulnerability_relationships_objects()
    import_advisory(advisory=advisory1, pipeline_name="test_importer2_pipeline")
    assert all_vulnerability_relation_objects == get_all_vulnerability_relationships_objects()
