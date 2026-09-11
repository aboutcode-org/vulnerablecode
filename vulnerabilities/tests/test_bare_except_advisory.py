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


def test_no_bare_except_in_advisory():
    """Test that advisory.py does not contain bare except clauses."""
    file_path = os.path.join(os.path.dirname(__file__), "..", "pipes", "advisory.py")
    with open(file_path, "r") as f:
        source = f.read()

    tree = ast.parse(source)

    bare_excepts = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            if node.type is None:
                bare_excepts.append(node.lineno)

    assert len(bare_excepts) == 0, f"Found bare except clauses at lines: {bare_excepts}"
