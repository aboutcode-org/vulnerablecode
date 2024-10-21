#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from vulnerabilities.importer import Importer


def test_all_importers_have_unique_name():
    importers = [importer.importer_name for importer in Importer.__subclasses__()]
    empty_importers = [
        importer.__name__ for importer in Importer.__subclasses__() if not importer.importer_name
    ]
    assert empty_importers == []
    assert len(importers) == len(set(importers))
