#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import os

import saneyaml

"""
Shared testing utilities
"""

# Used for tests to regenerate fixtures with regen=True: run a test with this
# env. var set to any value to regenarte expected result files. For example with:
# "VULNERABLECODE_REGEN_TEST_FIXTURES=yes pytest -vvs vulnerabilities/tests"
VULNERABLECODE_REGEN_TEST_FIXTURES = os.getenv("VULNERABLECODE_REGEN_TEST_FIXTURES", False)


def check_results_against_json(
    results,
    expected_file,
    regen=VULNERABLECODE_REGEN_TEST_FIXTURES,
):
    """
    Check the JSON-serializable mapping or sequence ``results`` against the
    expected  data in the JSON ``expected_file``

    If ``regen`` is True, the ``expected_file`` is overwritten with the
    ``results`` data. This is convenient for updating tests expectations.
    """
    if regen:
        with open(expected_file, "w") as reg:
            json.dump(results, reg, indent=2, separators=(",", ": "))
        expected = results
    else:
        with open(expected_file) as exp:
            expected = json.load(exp)

    check_results_against_expected(results, expected)


def check_results_against_expected(
    results,
    expected,
):
    """
    Check the JSON-serializable mapping or sequence ``results`` against the
    ``expected``.
    """
    # NOTE we redump the JSON as a YAML string for easier display of
    # the failures comparison/diff
    if results != expected:
        assert saneyaml.dump(results) == saneyaml.dump(expected)
