#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from datetime import datetime

import pytest
from univers.version_range import NpmVersionRange
from univers.versions import SemverVersion

from vulnerabilities.import_runner import ImportRunner
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.models import *
from vulnerabilities.pipelines.npm_importer import NpmImporterPipeline


@pytest.mark.django_db
def test_package_changelog():
    pkg, _ = Package.objects.get_or_create_from_purl("pkg:npm/foo@1.0.0")
    assert PackageChangeLog.objects.filter(package=pkg).count() == 0
    adv = Advisory.objects.create(
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
        aliases=["CVE-123"],
    )
    NpmImporterPipeline().import_advisory(advisory=adv)
    assert PackageChangeLog.objects.filter(package=pkg).count() == 1
    NpmImporterPipeline().import_advisory(advisory=adv)
    assert PackageChangeLog.objects.filter(package=pkg).count() == 1
    assert (
        PackageChangeLog.objects.filter(action_type=PackageChangeLog.FIXING, package=pkg).count()
        == 1
    )
    pkg1, _ = Package.objects.get_or_create_from_purl("pkg:npm/foo@2.0.0")
    assert PackageChangeLog.objects.filter(package=pkg1).count() == 0
    adv = Advisory.objects.create(
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
        aliases=["CVE-145"],
    )
    NpmImporterPipeline().import_advisory(advisory=adv)
    assert PackageChangeLog.objects.filter(package=pkg1).count() == 1
    NpmImporterPipeline().import_advisory(advisory=adv)
    assert PackageChangeLog.objects.filter(package=pkg1).count() == 1
    assert (
        PackageChangeLog.objects.filter(
            action_type=PackageChangeLog.AFFECTED_BY, package=pkg1
        ).count()
        == 1
    )


@pytest.mark.django_db
def test_vulnerability_changelog():
    adv = Advisory.objects.create(
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
        aliases=["CVE-TEST-1234"],
    )
    NpmImporterPipeline().import_advisory(advisory=adv)
    # 1 Changelogs is expected here:
    # 1 for importing vuln details
    assert VulnerabilityChangeLog.objects.count() == 1
    NpmImporterPipeline().import_advisory(advisory=adv)
    assert VulnerabilityChangeLog.objects.count() == 1
    assert (
        VulnerabilityChangeLog.objects.filter(action_type=VulnerabilityChangeLog.IMPORT).count()
        == 1
    )
