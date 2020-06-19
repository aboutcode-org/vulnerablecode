# Copyright (c)  nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an 'AS IS' BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import os
import json
from unittest import TestCase
from unittest.mock import patch
from unittest.mock import MagicMock
import xml.etree.ElementTree as ET

from vulnerabilities.package_managers import ComposerVersionAPI
from vulnerabilities.package_managers import MavenVersionAPI
from vulnerabilities.package_managers import NugetVersionAPI

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data")


class TestComposerVersionAPI(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.version_api = ComposerVersionAPI()
        with open(os.path.join(TEST_DATA, "composer_api", "cms-core.json")) as f:
            cls.response = json.load(f)

        cls.expected_versions = {
            "9.5.3",
            "8.7.30",
            "9.3.1",
            "9.5.1",
            "9.5.11",
            "9.5.6",
            "8.7.18",
            "8.7.15",
            "9.4.0",
            "9.5.7",
            "8.7.21",
            "9.5.12",
            "9.5.14",
            "8.7.27",
            "8.7.17",
            "8.7.9",
            "10.4.3",
            "10.0.0",
            "10.1.0",
            "9.5.13",
            "9.5.5",
            "8.7.22",
            "8.7.10",
            "8.7.24",
            "8.7.13",
            "8.7.14",
            "8.7.19",
            "9.5.17",
            "9.3.2",
            "9.5.15",
            "8.7.8",
            "9.3.3",
            "8.7.32",
            "10.4.0",
            "10.4.1",
            "9.5.18",
            "9.1.0",
            "9.5.19",
            "9.5.2",
            "8.7.26",
            "8.7.20",
            "10.2.0",
            "8.7.31",
            "8.7.11",
            "9.2.1",
            "8.7.25",
            "9.5.10",
            "10.2.2",
            "10.4.2",
            "9.5.9",
            "9.2.0",
            "9.3.0",
            "9.5.16",
            "10.3.0",
            "8.7.7",
            "10.4.4",
            "8.7.12",
            "8.7.29",
            "10.2.1",
            "9.5.8",
            "9.5.4",
            "9.5.0",
            "8.7.28",
            "8.7.23",
            "9.0.0",
            "8.7.16",
        }

    def test_composer_url(self):
        expected_url = "https://repo.packagist.org/p/typo3/cms-core.json"
        found_url = self.version_api.composer_url("typo3/cms-core")
        assert expected_url == found_url

    def test_extract_versions(self):

        found_versions = self.version_api.extract_versions(self.response, "typo3/cms-core")
        assert found_versions == self.expected_versions

    def test_load_to_api(self):

        assert self.version_api.get("typo3/cms-core") == set()

        mock_response = MagicMock()
        mock_response.json = lambda: self.response

        with patch("vulnerabilities.package_managers.requests.get", return_value=mock_response):
            self.version_api.load_to_api("typo3/cms-core")

        assert self.version_api.get("typo3/cms-core") == self.expected_versions


class TestMavenVersionAPI(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.version_api = MavenVersionAPI()
        with open(os.path.join(TEST_DATA, "maven_api", "maven-metadata.xml")) as f:
            cls.response = ET.parse(f)

    def test_artifact_url(self):
        eg_comps1 = ["org.apache", "kafka"]
        eg_comps2 = ["apple.msft.windows.mac.oss", "exfat-ntfs"]

        url1 = self.version_api.artifact_url(eg_comps1)
        url2 = self.version_api.artifact_url(eg_comps2)

        assert "https://repo.maven.apache.org/maven2/org/apache/kafka/maven-metadata.xml" == url1
        assert (
            "https://repo.maven.apache.org/maven2"
            "/apple/msft/windows/mac/oss/exfat-ntfs/maven-metadata.xml" == url2
        )

    def test_extract_versions(self):
        expected_versions = {"1.2.2", "1.2.3", "1.3.0"}
        assert expected_versions == self.version_api.extract_versions(self.response)

    def test_load_to_api(self):

        assert self.version_api.get("org.apache:kafka") == set()

        mock_response = MagicMock()
        mock_response.content = ET.tostring(self.response.getroot())
        expected = {"1.2.3", "1.3.0", "1.2.2"}

        with patch("vulnerabilities.package_managers.requests.get", return_value=mock_response):
            self.version_api.load_to_api("org.apache:kafka")

        assert self.version_api.get("org.apache:kafka") == expected


class TestNugetVersionAPI(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.version_api = NugetVersionAPI()
        with open(os.path.join(TEST_DATA, "nuget_api", "index.json")) as f:
            cls.response = json.load(f)

        cls.expected_versions = {
            "0.23.0",
            "0.24.0",
            "1.0.0",
            "1.0.1",
            "1.0.2",
            "2.0.0",
            "2.0.0-preview01",
            "2.6.0",
            "2.1.0",
            "2.2.0",
            "2.3.0",
            "2.4.0",
            "2.5.0",
            "2.7.0",
        }

    def test_nuget_url(self):
        expected_url = "https://api.nuget.org/v3/registration5-semver1/exfat.ntfs/index.json"
        found_url = self.version_api.nuget_url("exfat.ntfs")
        assert expected_url == found_url

    def test_extract_versions(self):

        found_versions = self.version_api.extract_versions(self.response)
        assert self.expected_versions == found_versions

    def test_load_to_api(self):

        assert self.version_api.get("Exfat.Ntfs") == set()

        mock_response = MagicMock()
        mock_response.json = lambda: self.response

        with patch("vulnerabilities.package_managers.requests.get", return_value=mock_response):
            self.version_api.load_to_api("Exfat.Ntfs")

        assert self.version_api.get("Exfat.Ntfs") == self.expected_versions
