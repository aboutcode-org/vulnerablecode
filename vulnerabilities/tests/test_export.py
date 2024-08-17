import os
from io import StringIO
from pathlib import Path
from unittest import TestCase

import pytest
import saneyaml
from django.core.management import call_command
from django.core.management.base import CommandError

from vulnerabilities.models import Alias
from vulnerabilities.models import Package
from vulnerabilities.models import PackageRelatedVulnerability
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import VulnerabilityRelatedReference
from vulnerabilities.models import VulnerabilitySeverity
from vulnerabilities.models import Weakness


@pytest.fixture
def package(db):
    return Package.objects.create(
        type="generic", namespace="nginx", name="test", version="2", qualifiers={}, subpath=""
    )


@pytest.fixture
def vulnerability_reference():
    return VulnerabilityReference.objects.create(
        reference_id="fake",
        url=f"https://..",
    )


@pytest.fixture
def vulnerability_severity(vulnerability_reference):
    return VulnerabilitySeverity.objects.create(
        scoring_system="cvssv3_vector",
        value="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        reference_id=vulnerability_reference.id,
    )


@pytest.fixture
def vulnerability(db, vulnerability_reference, vulnerability_severity):
    vulnerability = Vulnerability.objects.create(
        vulnerability_id="VCID-pst6-b358-aaap",
        summary="test-vuln",
    )
    Alias.objects.create(alias=f"CVE-xxx-xxx-xx", vulnerability=vulnerability)

    VulnerabilityRelatedReference.objects.create(
        reference=vulnerability_reference, vulnerability=vulnerability
    )

    weakness = Weakness.objects.create(cwe_id=15)
    vulnerability.weaknesses.add(weakness)

    return vulnerability


@pytest.fixture
def package_related_vulnerability(db, package, vulnerability):
    PackageRelatedVulnerability.objects.create(
        package=package,
        vulnerability=vulnerability,
        fix=False,
    )
    return package


class TestExportCommand(TestCase):
    def test_missing_path(self):
        with pytest.raises(CommandError) as cm:
            call_command("export", stdout=StringIO())

        err = str(cm)
        assert "Error: the following arguments are required: path" in err

    def test_bad_path_fail_error(self):
        with pytest.raises(CommandError) as cm:
            call_command("export", "/bad path", stdout=StringIO())

        err = str(cm)
        assert "Please enter a valid path" in err


@pytest.mark.django_db
def test_export_data(
    tmp_path, package_related_vulnerability, vulnerability_reference, vulnerability_severity
):
    expected_vul = {
        "vulnerability_id": "VCID-pst6-b358-aaap",
        "aliases": ["CVE-xxx-xxx-xx"],
        "summary": "test-vuln",
        "severities": [
            {
                "id": vulnerability_severity.id,
                "reference_id": vulnerability_reference.id,
                "scoring_system": "cvssv3_vector",
                "value": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "scoring_elements": "",
                "published_at": "",
            }
        ],
        "references": [
            {
                "id": vulnerability_reference.id,
                "url": "https://..",
                "reference_type": "",
                "reference_id": "fake",
            }
        ],
        "weaknesses": ["CWE-15"],
    }
    expected_pkg = {
        "package": "pkg:generic/nginx/test",
        "versions": [
            {
                "purl": "pkg:generic/nginx/test@2",
                "affected_by_vulnerabilities": ["VCID-pst6-b358-aaap"],
                "fixing_vulnerabilities": [],
            },
        ],
    }

    call_command("export", tmp_path, stdout=StringIO())

    vul_filepath = os.path.join(
        tmp_path,
        "./aboutcode-vulnerabilities-ps/b3/VCID-pst6-b358-aaap/VCID-pst6-b358-aaap.yml",
    )
    pkg_filepath = os.path.join(
        tmp_path,
        "./aboutcode-packages-2cf/generic/nginx/test/versions/vulnerabilities.yml",
    )

    assert Path(vul_filepath).read_text() == saneyaml.dump(expected_vul)
    assert Path(pkg_filepath).read_text() == saneyaml.dump(expected_pkg)
