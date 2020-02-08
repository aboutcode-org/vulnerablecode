#
# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
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

import pytest
import os
import json

from vulnerabilities.data_dump import debian_dump
from vulnerabilities.data_dump import ubuntu_dump
from vulnerabilities.data_dump import archlinux_dump
from vulnerabilities.importers import debian
from vulnerabilities.importers import ubuntu

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, 'test_data/')


@pytest.fixture
def setDebianData(db):
    with open(os.path.join(TEST_DATA, 'debian.json')) as f:
        test_data = json.load(f)

    extract_data = debian.extract_vulnerabilities(test_data)
    debian_dump(extract_data)


@pytest.fixture
def setUbuntuData(db):
    with open(os.path.join(TEST_DATA, 'ubuntu_main.html')) as f:
        test_data = f.read()

    data = ubuntu.extract_cves(test_data)
    ubuntu_dump(data)


@pytest.fixture
def setArchLinuxData(db):
    with open(os.path.join(TEST_DATA, 'archlinux.json')) as f:
        test_data = json.load(f)

    archlinux_dump(test_data)
