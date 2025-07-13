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

from vulnerabilities.models import AdvisorySeverity
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import AdvisoryWeakness
from vulnerabilities.models import PackageV2
from vulnerabilities.pipelines.v2_improvers.compute_package_risk import ComputePackageRiskPipeline
from vulnerabilities.severity_systems import CVSSV3
from vulnerabilities.severity_systems import GENERIC


@pytest.mark.django_db
def test_simple_risk_pipeline():
    pkg = PackageV2.objects.create(type="pypi", name="foo", version="2.3.0")
    assert PackageV2.objects.count() == 1

    adv = AdvisoryV2(
        advisory_id="VCID-Existing",
        summary="vulnerability description here",
        datasource_id="ds",
        avid="ds/VCID-Existing",
        unique_content_id="ajkef",
        url="https://test.com",
        date_collected=datetime.now(),
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

    adv.affecting_packages.add(pkg)
    adv.save()

    improver = ComputePackageRiskPipeline()
    improver.execute()

    assert pkg.risk_score is None

    improver = ComputePackageRiskPipeline()
    improver.execute()

    pkg = PackageV2.objects.get(type="pypi", name="foo", version="2.3.0")
    assert pkg.risk_score == Decimal("3.1")
