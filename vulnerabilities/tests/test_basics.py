#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


import subprocess
import sys
import unittest
from os.path import dirname
from os.path import join

root_dir = dirname(dirname(dirname(__file__)))
bin_dir = dirname(sys.executable)


class BaseTests(unittest.TestCase):
    def test_codestyle(self):
        args = join(bin_dir, "black --check -l 100 .")
        try:
            subprocess.check_output(args.split(), cwd=root_dir)
        except Exception as e:
            raise Exception(
                "Black style check failed, please format the code using black -l 100 . "
                "Alternatively, run ``make valid``"
            ) from e

        args = join(bin_dir, "isort --check-only .")
        try:
            subprocess.check_output(args.split(), cwd=root_dir)
        except Exception as e:
            raise Exception(
                "Unsorted imports, please sort your imports using isort. "
                "Alternatively, run ``make valid``"
            ) from e
