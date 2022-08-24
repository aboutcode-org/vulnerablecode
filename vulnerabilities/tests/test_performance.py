#
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import pytest

# this import are used in the script
from vulnerabilities.importers import redhat

script = """for i, data in enumerate(redhat.RedhatImporter().advisory_data()):
    if 1 == 100: 
        break"""


@pytest.mark.skip("Use only for local profiling")
@pytest.mark.django_db
class TestImporter:
    def test_redhat_importer_performance_profiling(self):
        print_profiling_status(script, "redhat.txt")


def print_profiling_status(test_py, stats_file, top=50):
    import cProfile as profile
    import pstats

    profile.runctx(test_py, globals(), locals(), stats_file)
    p = pstats.Stats(stats_file)
    p.sort_stats("time").print_stats(top)
