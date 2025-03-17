import unittest
from unittest.mock import Mock
from unittest.mock import patch

from django.test import TestCase

from vulnerabilities.models import Advisory
from vulnerabilities.models import Alias
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilitySeverity
from vulnerabilities.pipelines.add_cvss31_to_CVEs import CVEAdvisoryMappingPipeline
from vulnerabilities.severity_systems import CVSSV3
from vulnerabilities.severity_systems import CVSSV31


class TestCVEAdvisoryMappingPipeline(TestCase):
    def setUp(self):
        self.pipeline = CVEAdvisoryMappingPipeline()
        Advisory.objects.create(
            created_by="nvd_importer",
            aliases=["CVE-2024-1234"],
            references=[
                {
                    "severities": [
                        {
                            "system": "cvssv3.1",
                            "value": "7.5",
                            "scoring_elements": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        }
                    ],
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
                    "reference_id": "CVE-2024-1234",
                    "reference_type": "cve",
                }
            ],
            date_collected="2024-09-27T19:38:00Z",
        )
        vuln = Vulnerability.objects.create(vulnerability_id="CVE-2024-1234")
        sev = VulnerabilitySeverity.objects.create(
            scoring_system=CVSSV3.identifier,
            url="https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
            value="7.5",
            scoring_elements="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        )
        vuln.severities.add(sev)

    def test_process_cve_advisory_mapping_single_record(self):
        self.pipeline.process_cve_advisory_mapping()
        self.assertEqual(VulnerabilitySeverity.objects.count(), 2)
        # check if severity with cvssv3.1 is created
        sev = VulnerabilitySeverity.objects.get(scoring_system=CVSSV31.identifier)
        self.assertEqual(sev.url, "https://nvd.nist.gov/vuln/detail/CVE-2024-1234")
        self.assertEqual(sev.value, "7.5")
        self.assertEqual(sev.scoring_elements, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        # check if severity is added to existing vulnerability
        vuln = Vulnerability.objects.get(vulnerability_id="CVE-2024-1234")
        self.assertEqual(vuln.severities.count(), 2)
        self.assertIn(sev, vuln.severities.all())
