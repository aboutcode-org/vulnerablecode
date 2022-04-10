#
# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

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
            expected = exp.read()

    # NOTE we redump the JSON as a YAML string for easier display of
    # the failures comparison/diff
    if results != expected:
        expected = saneyaml.dump(expected)
        results = saneyaml.dump(results)
        assert results == expected
