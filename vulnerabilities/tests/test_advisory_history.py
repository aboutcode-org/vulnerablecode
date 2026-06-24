import json
import os

from vulnerabilities.templatetags.diff_advisory_history import format_diff_for_ui
from vulnerabilities.tests.util_tests import check_results_against_json


def test_advisory_history_diffing():
    """
    Test the diffing logic for historical advisory snapshots.
    """
    from vulnerabilities.utils import diff_advisories_v2

    base_dir = os.path.join(os.path.dirname(__file__), "test_data", "advisory_history")

    # Test GHSA-72hv-8253-57qq (Sample 1)
    # See: https://github.com/github/advisory-database/commits/main/advisories/github-reviewed/2026/02/GHSA-72hv-8253-57qq/GHSA-72hv-8253-57qq.json
    sample1_dir = os.path.join(base_dir, "GHSA-72hv-8253-57qq")
    with open(os.path.join(sample1_dir, "normalised_history_GHSA-72hv-8253-57qq.json"), "r") as f:
        sample1_data = json.load(f)

    sample1_diffs = [
        diff_advisories_v2(sample1_data[i], sample1_data[i + 1])
        for i in range(len(sample1_data) - 1)
    ]

    sample1_expected_file = os.path.join(sample1_dir, "expected_diff_GHSA-72hv-8253-57qq.json")
    check_results_against_json(sample1_diffs, sample1_expected_file)

    # Test GHSA-6rw7-vpxm-498p (Sample 2)
    # See: https://github.com/github/advisory-database/commits/main/advisories/github-reviewed/2025/12/GHSA-6rw7-vpxm-498p/GHSA-6rw7-vpxm-498p.json
    sample2_dir = os.path.join(base_dir, "GHSA-6rw7-vpxm-498p")
    with open(os.path.join(sample2_dir, "normalised_history_GHSA-6rw7-vpxm-498p.json"), "r") as f:
        sample2_data = json.load(f)

    sample2_diffs = [
        diff_advisories_v2(sample2_data[i], sample2_data[i + 1])
        for i in range(len(sample2_data) - 1)
    ]

    sample2_expected_file = os.path.join(sample2_dir, "expected_diff_GHSA-6rw7-vpxm-498p.json")
    check_results_against_json(sample2_diffs, sample2_expected_file)


def test_format_diff_for_ui():
    """
    Test the template tag logic that formats diffs for the UI.
    """
    base_dir = os.path.join(os.path.dirname(__file__), "test_data", "advisory_history")
    sample2_dir = os.path.join(base_dir, "GHSA-6rw7-vpxm-498p")
    input_file = os.path.join(sample2_dir, "expected_diff_GHSA-6rw7-vpxm-498p.json")

    with open(input_file, "r") as f:
        input_diffs = json.load(f)

    formatted_diffs = [format_diff_for_ui(diff) for diff in input_diffs]

    expected_file = os.path.join(sample2_dir, "expected_formatted_diff_GHSA-6rw7-vpxm-498p.json")
    check_results_against_json(formatted_diffs, expected_file)
