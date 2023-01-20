import os
from unittest import mock

import pytest

from vulnerabilities.import_runner import ImportRunner
from vulnerabilities.importers.nginx import NginxImporter
from vulnerabilities.improve_runner import ImproveRunner
from vulnerabilities.improvers.default import DefaultImprover
from vulnerabilities.models import Package
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data", "nginx")


@pytest.mark.django_db
@mock.patch("vulnerabilities.importers.nginx.NginxImporter.fetch")
def test_deletion_of_advisories(fetch):
    """Test that the deletion of advisories works as expected."""
    with open(os.path.join(TEST_DATA, "security_advisories.html")) as f:
        fetch.return_value = f.read()

    ImportRunner(NginxImporter).run()
    ImproveRunner(DefaultImprover).run()
    packages = Package.objects.all().only("id")
    packages_before_deletion = [int(package.id) for package in packages]
    vulnerabilities = Vulnerability.objects.all().only("id")
    vulnerabilities_before_deletion = [int(vulnerability.id) for vulnerability in vulnerabilities]
    references = VulnerabilityReference.objects.all().only("id")
    references_before_deletion = [int(reference.id) for reference in references]
    ImportRunner(NginxImporter).run()
    ImproveRunner(DefaultImprover).run()
    packages = Package.objects.all().only("id")
    packages_after_deletion = [int(package.id) for package in packages]
    vulnerabilities = Vulnerability.objects.all().only("id")
    vulnerabilities_after_deletion = [int(vulnerability.id) for vulnerability in vulnerabilities]
    references = VulnerabilityReference.objects.all().only("id")
    references_after_deletion = [int(reference.id) for reference in references]
    assert packages_before_deletion == packages_after_deletion
    assert vulnerabilities_before_deletion == vulnerabilities_after_deletion
    assert references_before_deletion == references_after_deletion
