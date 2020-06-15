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

import os
import unittest

from vulnerabilities.importers.github import GitHubAPIDataSource
from vulnerabilities.importers.github import MavenVersionAPI

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data")


class TestGitHubAPIDataSource(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data_source_cfg = {
            "endpoint": "https://api.example.com/graphql",
            "ecosystems": ["MAVEN"],
        }
        cls.data_src = GitHubAPIDataSource(1, config=data_source_cfg)

    def test_categorize_versions(self):
        eg_version_range = ">= 3.3.0, < 3.3.5"
        eg_versions = {"3.3.6", "3.3.0", "3.3.4", "3.2.0"}

        aff_vers, safe_vers = self.data_src.categorize_versions(
            eg_version_range, eg_versions
        )
        exp_safe_vers = {"3.3.6", "3.2.0"}
        exp_aff_vers = {"3.3.0", "3.3.4"}

        assert aff_vers == exp_aff_vers
        assert safe_vers == exp_safe_vers


class TestMavenVersionAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.version_api = MavenVersionAPI()

    def test_artifact_url(self):
        eg_comps1 = ["org.apache", "kafka"]
        eg_comps2 = ["apple.msft.windows.mac.oss", "exfat-ntfs"]

        url1 = self.version_api.artifact_url(eg_comps1)
        url2 = self.version_api.artifact_url(eg_comps2)

        assert (
            "https://repo.maven.apache.org/maven2/org/apache/kafka/maven-metadata.xml"
            == url1
        )
        assert (
            "https://repo.maven.apache.org/maven2"
            "/apple/msft/windows/mac/oss/exfat-ntfs/maven-metadata.xml" == url2
        )
