#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import pytest

from vulnerabilities.models import AffectedByPackageRelatedVulnerability
from vulnerabilities.models import Package
from vulnerabilities.pipelines.compute_package_risk import ComputePackageRiskPipeline
from vulnerabilities.tests.test_risk import vulnerability


@pytest.mark.django_db
def test_simple_risk_pipeline(vulnerability):
    pkg = Package.objects.create(type="pypi", name="foo", version="2.3.0")
    assert Package.objects.count() == 1

    improver = ComputePackageRiskPipeline()
    improver.execute()

    assert pkg.risk_score is None

    AffectedByPackageRelatedVulnerability.objects.create(package=pkg, vulnerability=vulnerability)
    improver = ComputePackageRiskPipeline()
    improver.execute()

    pkg = Package.objects.get(type="pypi", name="foo", version="2.3.0")
    assert str(pkg.risk_score) == str(3.11)
