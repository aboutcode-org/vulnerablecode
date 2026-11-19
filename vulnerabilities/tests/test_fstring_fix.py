#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import ast
import os


def test_no_fstring_without_placeholders_in_vulnrichment():
    """Test that vulnrichment.py does not contain f-strings without placeholders."""
    file_path = os.path.join(os.path.dirname(__file__), "..", "importers", "vulnrichment.py")
    with open(file_path, "r") as f:
        source = f.read()

    tree = ast.parse(source)

    empty_fstrings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            if all(isinstance(v, ast.Constant) for v in node.values):
                empty_fstrings.append(node.lineno)

    assert (
        len(empty_fstrings) == 0
    ), f"Found f-strings without placeholders at lines: {empty_fstrings}"
