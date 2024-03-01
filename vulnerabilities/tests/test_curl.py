#
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
from unittest.mock import patch

import requests
from bs4 import BeautifulSoup

# from importer import AdvisoryData
from univers.versions import SemverVersion

from vulnerabilities.importers import curl
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/curl")


def test_is_semver_version():
    url = "https://curl.se/docs/releases.html"

    response = requests.get(url)

    if response.status_code == 200:
        soup = BeautifulSoup(response.text, "html.parser")
        rows = soup.find_all("tr")
        versions = []
        for row in rows:

            cells = row.find_all("td")
            if len(cells) >= 2:
                version = cells[1].get_text().strip()
                versions.append(version)
        c = 0
        for version in versions:
            semver_version = SemverVersion(version)
            if semver_version.is_valid(version):
                c += 1
        if c == len(versions):
            print("All versions of curl are SemVer versions.")
        else:
            print("Not all versions are SemVer versions.")
    else:
        print("Failed to retrieve data from the webpage")
