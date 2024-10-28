import pytest

from vulnerabilities.models import AffectedByPackageRelatedVulnerability
from vulnerabilities.models import Package
from vulnerabilities.pipelines.risk_package import ComputePackageRiskPipeline
from vulnerabilities.tests.test_risk import vulnerability


@pytest.mark.django_db
def test_simple_risk_pipeline(vulnerability):
    pkg = Package.objects.create(type="pypi", name="foo", version="2.3.0")
    assert Package.objects.count() == 1

    improver = ComputePackageRiskPipeline()
    improver.execute()

    assert pkg.risk is None

    AffectedByPackageRelatedVulnerability.objects.create(package=pkg, vulnerability=vulnerability)
    improver = ComputePackageRiskPipeline()
    improver.execute()

    pkg = Package.objects.get(type="pypi", name="foo", version="2.3.0")
    assert str(pkg.risk) == str(3.11)
