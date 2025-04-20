#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from datetime import datetime
from unittest.mock import patch

import pytest
from packageurl import PackageURL
from univers.version_range import NpmVersionRange
from univers.versions import SemverVersion

from vulnerabilities import models
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.pipelines.npm_importer import NpmImporterPipeline
from vulnerabilities.pipes.advisory import get_or_create_aliases


@pytest.mark.django_db
def test_package_changelog():
    pkg, _ = models.Package.objects.get_or_create_from_purl("pkg:npm/foo@1.0.0")
    assert models.PackageChangeLog.objects.filter(package=pkg).count() == 0
    adv = models.Advisory.objects.create(
        unique_content_id="test-unique-content-id1",
        created_by=NpmImporterPipeline.pipeline_id,
        summary="TEST",
        date_collected=datetime.now(),
        url="https://test.com/source",
        affected_packages=[
            AffectedPackage(
                package=PackageURL(
                    type="npm",
                    name="foo",
                ),
                fixed_version=SemverVersion("1.0"),
            ).to_dict()
        ],
    )
    adv.aliases.add(*get_or_create_aliases(["CVE-123"]))
    NpmImporterPipeline().import_advisory(advisory=adv)
    assert models.PackageChangeLog.objects.filter(package=pkg).count() == 1
    NpmImporterPipeline().import_advisory(advisory=adv)
    assert models.PackageChangeLog.objects.filter(package=pkg).count() == 1
    assert (
        models.PackageChangeLog.objects.filter(
            action_type=models.PackageChangeLog.FIXING, package=pkg
        ).count()
        == 1
    )
    pkg1, _ = models.Package.objects.get_or_create_from_purl("pkg:npm/foo@2.0.0")
    assert models.PackageChangeLog.objects.filter(package=pkg1).count() == 0
    adv = models.Advisory.objects.create(
        unique_content_id="test-unique-content-id2",
        created_by=NpmImporterPipeline.pipeline_id,
        summary="TEST-1",
        date_collected=datetime.now(),
        url="https://test.com/source-1",
        affected_packages=[
            AffectedPackage(
                package=PackageURL(
                    type="npm",
                    name="foo",
                ),
                affected_version_range=NpmVersionRange.from_native(">=2.0"),
            ).to_dict()
        ],
    )
    adv.aliases.add(*get_or_create_aliases(["CVE-123"]))
    NpmImporterPipeline().import_advisory(advisory=adv)
    assert models.PackageChangeLog.objects.filter(package=pkg1).count() == 1
    NpmImporterPipeline().import_advisory(advisory=adv)
    assert models.PackageChangeLog.objects.filter(package=pkg1).count() == 1
    assert (
        models.PackageChangeLog.objects.filter(
            action_type=models.PackageChangeLog.AFFECTED_BY,
            package=pkg1,
        ).count()
        == 1
    )


@pytest.mark.django_db
def test_vulnerability_changelog():
    adv = models.Advisory.objects.create(
        unique_content_id="test-unique-content-id3",
        created_by=NpmImporterPipeline.pipeline_id,
        summary="TEST_1",
        date_collected=datetime.now(),
        url="https://test.com/source",
        affected_packages=[
            AffectedPackage(
                package=PackageURL(
                    type="npm",
                    name="foo",
                ),
                fixed_version=SemverVersion("1.0"),
            ).to_dict()
        ],
    )
    adv.aliases.add(*get_or_create_aliases(["CVE-TEST-1234"]))
    NpmImporterPipeline().import_advisory(advisory=adv)
    # 1 Changelogs is expected here:
    # 1 for importing vuln details
    assert models.VulnerabilityChangeLog.objects.count() == 1
    NpmImporterPipeline().import_advisory(advisory=adv)
    assert models.VulnerabilityChangeLog.objects.count() == 1
    assert (
        models.VulnerabilityChangeLog.objects.filter(
            action_type=models.VulnerabilityChangeLog.IMPORT
        ).count()
        == 1
    )


@patch("vulnerabilities.models.VULNERABLECODE_VERSION", "test-version")
@pytest.mark.django_db
def test_vulnerability_changelog_software_version():
    adv = models.Advisory.objects.create(
        unique_content_id="test-unique-content-id4",
        created_by=NpmImporterPipeline.pipeline_id,
        summary="TEST_1",
        date_collected=datetime.now(),
        url="https://test.com/source",
        affected_packages=[
            AffectedPackage(
                package=PackageURL(
                    type="npm",
                    name="foo",
                ),
                fixed_version=SemverVersion("1.0"),
            ).to_dict()
        ],
    )
    adv.aliases.add(*get_or_create_aliases(["CVE-TEST-1234"]))
    NpmImporterPipeline().import_advisory(advisory=adv)
    npm_vulnerability_log = models.VulnerabilityChangeLog.objects.first()

    assert ("test-version", npm_vulnerability_log.software_version)
