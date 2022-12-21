import json
import os

from vulnerabilities.importers.xen import XenImporter
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(
    BASE_DIR,
    "test_data",
)


def test_xen_to_advisories():
    with open(os.path.join(TEST_DATA, "xen_data.json")) as f:
        raw_data = json.load(f)
    advisories = XenImporter().to_advisories(raw_data)
    result = [data.to_dict() for data in advisories]
    expected_file = os.path.join(TEST_DATA, f"parse-advisory-xen-expected.json")
    util_tests.check_results_against_json(result, expected_file)
