#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from datetime import datetime
from decimal import Decimal

import pytest
from django.utils import timezone

from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import AdvisorySeverity
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import AdvisoryWeakness
from vulnerabilities.models import EPSSScore
from vulnerabilities.models import ImpactedPackage
from vulnerabilities.models import PackageV2
from vulnerabilities.pipelines.v2_improvers.compute_package_risk import ComputePackageRiskPipeline
from vulnerabilities.severity_systems import CVSSV3
from vulnerabilities.severity_systems import GENERIC


@pytest.mark.django_db
def test_simple_risk_pipeline():
    pkg = PackageV2.objects.create(type="pypi", name="foo", version="2.3.0")
    assert PackageV2.objects.count() == 1

    cur = timezone.now()

    adv = AdvisoryV2(
        advisory_id="VCID-Existing",
        summary="vulnerability description here",
        datasource_id="ds",
        pipeline_id="ds_importer_v2",
        avid="ds/VCID-Existing",
        unique_content_id="ajkef",
        url="https://test.com",
        date_collected=datetime.now(),
        is_latest=True,
        _all_impacts_unfurled_at=cur,
    )
    adv.save()

    severity1 = AdvisorySeverity.objects.create(
        url="https://nvd.nist.gov/vuln/detail/CVE-xxxx-xxx1",
        scoring_system=CVSSV3.identifier,
        scoring_elements="CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L",
        value="6.5",
    )

    severity2 = AdvisorySeverity.objects.create(
        url="https://nvd.nist.gov/vuln/detail/CVE-xxxx-xxx1",
        scoring_system=GENERIC.identifier,
        value="MODERATE",  # 6.9
    )
    adv.severities.add(severity1)
    adv.severities.add(severity2)

    weaknesses = AdvisoryWeakness.objects.create(cwe_id=119)
    adv.weaknesses.add(weaknesses)

    impact = ImpactedPackage.objects.create(advisory=adv)
    impact.affecting_packages.add(pkg)

    improver = ComputePackageRiskPipeline()
    improver.execute()

    assert pkg.risk_score is None

    improver = ComputePackageRiskPipeline()
    improver.execute()

    pkg = PackageV2.objects.get(type="pypi", name="foo", version="2.3.0")
    assert pkg.risk_score == Decimal("3.1")


@pytest.mark.django_db
def test_compute_package_risk_pipeline_with_high_epss():
    package = PackageV2.objects.create(type="pypi", name="bar", version="1.0.0")
    now = timezone.now()

    alias = AdvisoryAlias.objects.create(alias="CVE-2024-9999")
    EPSSScore.objects.create(
        alias=alias,
        date=now.date(),
        score=Decimal("0.85"),
        percentile=Decimal("0.99"),
        is_latest=True,
    )

    advisory = AdvisoryV2.objects.create(
        advisory_id="VCID-High-EPSS",
        summary="vulnerability with high epss score",
        datasource_id="ds",
        pipeline_id="ds_importer_v2",
        avid="ds/VCID-High-EPSS",
        unique_content_id="unique_epss_1",
        url="https://test.com",
        date_collected=now,
        is_latest=True,
        _all_impacts_unfurled_at=now,
    )
    advisory.aliases.add(alias)

    severity = AdvisorySeverity.objects.create(
        url="https://nvd.nist.gov/vuln/detail/CVE-xxxx-xxx1",
        scoring_system=CVSSV3.identifier,
        value="6.5",
    )
    advisory.severities.add(severity)

    impact = ImpactedPackage.objects.create(advisory=advisory)
    impact.affecting_packages.add(package)

    pipeline = ComputePackageRiskPipeline()
    pipeline.execute()

    advisory.refresh_from_db()
    package.refresh_from_db()
    assert advisory.exploitability == Decimal("2.0")
    assert advisory.risk_score == Decimal("10.0")
    assert package.risk_score == Decimal("10.0")
