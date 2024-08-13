import json
import os
from unittest import TestCase

from vulnerabilities.importers.vulnrichment import parse_cve_advisory
from vulnerabilities.importers.vulnrichment import ssvc_calculator
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/vulnrichment")


class TestVulnrichmentImporter(TestCase):
    def test_to_advisories1(self):
        with open(os.path.join(TEST_DATA, "vulnrichment-data1.json")) as f:
            mock_response = json.load(f)
        expected_file = os.path.join(TEST_DATA, "vulnrichment-data1-expected.json")
        imported_data = parse_cve_advisory(mock_response, advisory_url="http://test.com")
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisorie2(self):
        with open(os.path.join(TEST_DATA, "vulnrichment-data2.json")) as f:
            mock_response = json.load(f)
        expected_file = os.path.join(TEST_DATA, "vulnrichment-data2-expected.json")
        imported_data = parse_cve_advisory(mock_response, advisory_url="http://test.com")
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisorie3(self):
        with open(os.path.join(TEST_DATA, "vulnrichment-data3.json")) as f:
            mock_response = json.load(f)
        expected_file = os.path.join(TEST_DATA, "vulnrichment-data3-expected.json")
        imported_data = parse_cve_advisory(mock_response, advisory_url="http://test.com")
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_make_ssvc_vector1(self):
        assert ssvc_calculator(
            {
                "id": "CVE-2024-5396",
                "role": "CISA Coordinator",
                "options": [
                    {"Exploitation": "poc"},
                    {"Automatable": "no"},
                    {"Technical Impact": "partial"},
                ],
                "version": "2.0.3",
                "timestamp": "2024-05-28T15:58:04.187512Z",
            }
        ) == ("SSVCv2/E:P/A:N/T:P/P:M/B:A/M:M/D:T/2024-05-28T15:58:04Z/", "Track")

    def test_make_ssvc_vector2(self):
        assert ssvc_calculator(
            {
                "id": "CVE-2024-5396",
                "role": "CISA Coordinator",
                "options": [
                    {"Exploitation": "active"},
                    {"Automatable": "no"},
                    {"Technical Impact": "total"},
                    {"Mission Prevalence": "Minimal"},
                    {"Public Well-being Impact": "Material"},
                    {"Mission & Well-being": "medium"},
                ],
                "version": "2.0.3",
                "timestamp": "2024-05-28T15:58:04.187512Z",
            }
        ) == ("SSVCv2/E:A/A:N/T:T/P:M/B:A/M:M/D:A/2024-05-28T15:58:04Z/", "Attend")
