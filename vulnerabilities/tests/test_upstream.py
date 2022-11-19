#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import pytest

from vulnerabilities.importers import IMPORTERS_REGISTRY


@pytest.mark.webtest
@pytest.mark.parametrize(
    ("importer_name", "importer_class"),
    IMPORTERS_REGISTRY.items(),
)
def test_updated_advisories(importer_name, importer_class):
    # FIXME: why are we doing this?
    if importer_name.endswith("GitHubAPIImporter"):
        return

    advisory_datas = importer_class().advisory_data()
    for advisory_data in advisory_datas:
        # stop after a single import
        break

    # check that we have at least one advisory_data
    assert advisory_data.to_dict()
