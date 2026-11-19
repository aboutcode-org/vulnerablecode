
from django.test import TestCase
from vulnerabilities.models import VulnerabilitySeverity, AdvisorySeverity
from vulnerabilities.severity_systems import SCORING_SYSTEMS

class TestSeverityStorage(TestCase):
    def test_scoring_elements_data_population_vulnerability(self):
        # CVSS v3.1 vector
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        severity = VulnerabilitySeverity.objects.create(
            scoring_system="cvssv3.1",
            scoring_elements=vector,
            value="9.8"
        )
        severity.refresh_from_db()
        self.assertTrue(severity.scoring_elements_data)
        self.assertEqual(severity.scoring_elements_data['version'], '3.1')
        self.assertEqual(severity.scoring_elements_data['vectorString'], vector)

    def test_scoring_elements_data_population_advisory(self):
        # CVSS v2 vector
        vector = "AV:N/AC:L/Au:N/C:P/I:P/A:P"
        severity = AdvisorySeverity.objects.create(
            scoring_system="cvssv2",
            scoring_elements=vector,
            value="7.5"
        )
        severity.refresh_from_db()
        self.assertTrue(severity.scoring_elements_data)
        self.assertEqual(severity.scoring_elements_data['version'], '2.0')
        self.assertEqual(severity.scoring_elements_data['vectorString'], vector)
