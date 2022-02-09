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

import asyncio
import distutils.spawn
import json
import os
from unittest.case import SkipTest
import xml.etree.ElementTree as ET
from datetime import datetime
from aiohttp.client import ClientSession
from dateutil.tz import tzlocal, tzutc
from pytz import UTC
from unittest import TestCase
from unittest.mock import AsyncMock

from vulnerabilities.package_managers import ComposerVersionAPI
from vulnerabilities.package_managers import GoproxyVersionAPI
from vulnerabilities.package_managers import MavenVersionAPI
from vulnerabilities.package_managers import NugetVersionAPI
from vulnerabilities.package_managers import GitHubTagsAPI
from vulnerabilities.package_managers import Version
from vulnerabilities.package_managers import VersionResponse
from vulnerabilities.package_managers import client_session

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data")


class MockClientSession:
    def __init__(self, return_val):
        self.return_val = return_val

    async def request(self, *args, **kwargs):
        mock_response = AsyncMock()
        mock_response.json = self.json
        mock_response.read = self.read
        mock_response.text = self.text
        return mock_response

    def get(self, *args, **kwargs):
        kwargs["method"] = "get"
        return self.request(*args, **kwargs)

    def post(self, *args, **kwargs):
        kwargs["method"] = "post"
        return self.request(*args, **kwargs)

    async def json(self):
        return self.return_val

    async def read(self):
        return self.return_val

    async def text(self):
        return self.return_val


class RecordedClientSession:
    def __init__(self, test_id, regen=False):
        self.test_id = test_id
        self.req_num = 1
        self.headers = {}
        self.regen = regen
        if regen:
            self.session = ClientSession()

    @property
    def record_filename(self):
        return os.path.join(TEST_DATA, "records", f"{self.test_id}_{self.req_num}.json")

    async def request(self, *args, **kwargs):
        if self.regen:
            self.session.headers.update(self.headers)
            res = await self.session.request(*args, **kwargs)
            data = await res.read()
            with open(self.record_filename, "wb") as f:
                f.write(data)
        with open(self.record_filename, "rb") as f:
            self.return_val = f.read()

        mock_response = AsyncMock()
        mock_response.json = self.json
        mock_response.read = self.read
        self.req_num += 1
        return mock_response

    def get(self, *args, **kwargs):
        return self.request("get", *args, **kwargs)

    def post(self, *args, **kwargs):
        return self.request("post", *args, **kwargs)

    async def json(self):
        return json.loads(self.return_val)

    async def read(self):
        return self.return_val

    async def __aenter__(self):
        if self.regen:
            await self.session.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.regen:
            return await self.session.__aexit__(exc_type, exc, tb)


class TestComposerVersionAPI(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.version_api = ComposerVersionAPI()
        with open(os.path.join(TEST_DATA, "composer_api", "cms-core.json")) as f:
            cls.response = json.load(f)

        cls.expected_versions = {
            Version(
                value="8.7.10",
                release_date=datetime(2018, 2, 6, 10, 46, 2, tzinfo=tzlocal()),
            ),
            Version(
                value="8.7.11",
                release_date=datetime(2018, 3, 13, 12, 44, 45, tzinfo=tzlocal()),
            ),
            Version(
                value="8.7.12",
                release_date=datetime(2018, 3, 22, 11, 35, 42, tzinfo=tzlocal()),
            ),
            Version(
                value="8.7.13",
                release_date=datetime(2018, 4, 17, 8, 15, 46, tzinfo=tzlocal()),
            ),
            Version(
                value="8.7.14",
                release_date=datetime(2018, 5, 22, 13, 51, 9, tzinfo=tzlocal()),
            ),
            Version(
                value="8.7.15",
                release_date=datetime(2018, 5, 23, 11, 31, 21, tzinfo=tzlocal()),
            ),
            Version(
                value="8.7.16",
                release_date=datetime(2018, 6, 11, 17, 18, 14, tzinfo=tzlocal()),
            ),
            Version(
                value="8.7.17",
                release_date=datetime(2018, 7, 12, 11, 29, 19, tzinfo=tzlocal()),
            ),
            Version(
                value="8.7.18",
                release_date=datetime(2018, 7, 31, 8, 15, 29, tzinfo=tzlocal()),
            ),
            Version(
                value="8.7.19",
                release_date=datetime(2018, 8, 21, 7, 23, 21, tzinfo=tzlocal()),
            ),
            Version(
                value="8.7.21",
                release_date=datetime(2018, 12, 11, 12, 40, 12, tzinfo=tzlocal()),
            ),
            Version(
                value="8.7.20",
                release_date=datetime(2018, 10, 30, 10, 39, 51, tzinfo=tzlocal()),
            ),
            Version(
                value="8.7.22",
                release_date=datetime(2018, 12, 14, 7, 43, 50, tzinfo=tzlocal()),
            ),
            Version(
                value="8.7.23",
                release_date=datetime(2019, 1, 22, 10, 10, 2, tzinfo=tzlocal()),
            ),
            Version(
                value="8.7.24",
                release_date=datetime(2019, 1, 22, 15, 25, 55, tzinfo=tzlocal()),
            ),
            Version(
                value="8.7.25",
                release_date=datetime(2019, 5, 7, 10, 5, 55, tzinfo=tzlocal()),
            ),
            Version(
                value="8.7.26",
                release_date=datetime(2019, 5, 15, 11, 24, 12, tzinfo=tzlocal()),
            ),
            Version(
                value="8.7.27",
                release_date=datetime(2019, 6, 25, 8, 24, 21, tzinfo=tzlocal()),
            ),
            Version(
                value="8.7.28",
                release_date=datetime(2019, 10, 15, 7, 21, 52, tzinfo=tzlocal()),
            ),
            Version(
                value="8.7.29",
                release_date=datetime(2019, 10, 30, 21, 0, 45, tzinfo=tzlocal()),
            ),
            Version(
                value="8.7.30",
                release_date=datetime(2019, 12, 17, 10, 49, 17, tzinfo=tzlocal()),
            ),
            Version(
                value="8.7.31",
                release_date=datetime(2020, 2, 17, 23, 29, 16, tzinfo=tzlocal()),
            ),
            Version(
                value="8.7.7",
                release_date=datetime(2017, 9, 19, 14, 22, 53, tzinfo=tzlocal()),
            ),
            Version(
                value="8.7.32",
                release_date=datetime(2020, 3, 31, 8, 33, 3, tzinfo=tzlocal()),
            ),
            Version(
                value="8.7.8",
                release_date=datetime(2017, 10, 10, 16, 8, 44, tzinfo=tzlocal()),
            ),
            Version(
                value="8.7.9",
                release_date=datetime(2017, 12, 12, 16, 9, 50, tzinfo=tzlocal()),
            ),
            Version(
                value="9.0.0",
                release_date=datetime(2017, 12, 12, 16, 48, 22, tzinfo=tzlocal()),
            ),
            Version(
                value="9.1.0",
                release_date=datetime(2018, 1, 30, 15, 31, 12, tzinfo=tzlocal()),
            ),
            Version(
                value="9.2.0",
                release_date=datetime(2018, 4, 9, 20, 51, 35, tzinfo=tzlocal()),
            ),
            Version(
                value="9.2.1",
                release_date=datetime(2018, 5, 22, 13, 47, 11, tzinfo=tzlocal()),
            ),
            Version(
                value="9.3.0",
                release_date=datetime(2018, 6, 11, 17, 14, 33, tzinfo=tzlocal()),
            ),
            Version(
                value="9.3.1",
                release_date=datetime(2018, 7, 12, 11, 33, 12, tzinfo=tzlocal()),
            ),
            Version(
                value="9.3.2",
                release_date=datetime(2018, 7, 12, 15, 51, 49, tzinfo=tzlocal()),
            ),
            Version(
                value="9.3.3",
                release_date=datetime(2018, 7, 31, 8, 20, 17, tzinfo=tzlocal()),
            ),
            Version(
                value="9.5.0",
                release_date=datetime(2018, 10, 2, 8, 10, 33, tzinfo=tzlocal()),
            ),
            Version(
                value="9.4.0",
                release_date=datetime(2018, 9, 4, 12, 8, 20, tzinfo=tzlocal()),
            ),
            Version(
                value="9.5.1",
                release_date=datetime(2018, 10, 30, 10, 45, 30, tzinfo=tzlocal()),
            ),
            Version(
                value="9.5.10",
                release_date=datetime(2019, 10, 15, 7, 29, 55, tzinfo=tzlocal()),
            ),
            Version(
                value="9.5.11",
                release_date=datetime(2019, 10, 30, 20, 46, 49, tzinfo=tzlocal()),
            ),
            Version(
                value="9.5.12",
                release_date=datetime(2019, 12, 17, 10, 53, 45, tzinfo=tzlocal()),
            ),
            Version(
                value="9.5.13",
                release_date=datetime(2019, 12, 17, 14, 17, 37, tzinfo=tzlocal()),
            ),
            Version(
                value="9.5.14",
                release_date=datetime(2020, 2, 17, 23, 37, 2, tzinfo=tzlocal()),
            ),
            Version(
                value="9.5.15",
                release_date=datetime(2020, 3, 31, 8, 40, 25, tzinfo=tzlocal()),
            ),
            Version(
                value="9.5.16",
                release_date=datetime(2020, 4, 28, 9, 22, 14, tzinfo=tzlocal()),
            ),
            Version(
                value="9.5.17",
                release_date=datetime(2020, 5, 12, 10, 36, tzinfo=tzlocal()),
            ),
            Version(
                value="9.5.18",
                release_date=datetime(2020, 5, 19, 13, 10, 50, tzinfo=tzlocal()),
            ),
            Version(
                value="9.5.2",
                release_date=datetime(2018, 12, 11, 12, 42, 55, tzinfo=tzlocal()),
            ),
            Version(
                value="9.5.19",
                release_date=datetime(2020, 6, 9, 8, 44, 34, tzinfo=tzlocal()),
            ),
            Version(
                value="9.5.3",
                release_date=datetime(2018, 12, 14, 7, 28, 48, tzinfo=tzlocal()),
            ),
            Version(
                value="9.5.4",
                release_date=datetime(2019, 1, 22, 10, 12, 4, tzinfo=tzlocal()),
            ),
            Version(
                value="9.5.5",
                release_date=datetime(2019, 3, 4, 20, 25, 8, tzinfo=tzlocal()),
            ),
            Version(
                value="9.5.6",
                release_date=datetime(2019, 5, 7, 10, 16, 30, tzinfo=tzlocal()),
            ),
            Version(
                value="9.5.7",
                release_date=datetime(2019, 5, 15, 11, 41, 51, tzinfo=tzlocal()),
            ),
            Version(
                value="9.5.8",
                release_date=datetime(2019, 6, 25, 8, 28, 51, tzinfo=tzlocal()),
            ),
            Version(
                value="9.5.9",
                release_date=datetime(2019, 8, 20, 9, 33, 35, tzinfo=tzlocal()),
            ),
            Version(
                value="10.0.0",
                release_date=datetime(2019, 7, 23, 7, 6, 3, tzinfo=tzlocal()),
            ),
            Version(
                value="10.1.0",
                release_date=datetime(2019, 10, 1, 8, 18, 18, tzinfo=tzlocal()),
            ),
            Version(
                value="10.2.0",
                release_date=datetime(2019, 12, 3, 11, 16, 26, tzinfo=tzlocal()),
            ),
            Version(
                value="10.2.1",
                release_date=datetime(2019, 12, 17, 11, 0, tzinfo=tzlocal()),
            ),
            Version(
                value="10.2.2",
                release_date=datetime(2019, 12, 17, 11, 36, 14, tzinfo=tzlocal()),
            ),
            Version(
                value="10.3.0",
                release_date=datetime(2020, 2, 25, 12, 50, 9, tzinfo=tzlocal()),
            ),
            Version(
                value="10.4.0",
                release_date=datetime(2020, 4, 21, 8, 0, 15, tzinfo=tzlocal()),
            ),
            Version(
                value="10.4.1",
                release_date=datetime(2020, 4, 28, 9, 7, 54, tzinfo=tzlocal()),
            ),
            Version(
                value="10.4.2",
                release_date=datetime(2020, 5, 12, 10, 41, 40, tzinfo=tzlocal()),
            ),
            Version(
                value="10.4.4",
                release_date=datetime(2020, 6, 9, 8, 56, 30, tzinfo=tzlocal()),
            ),
            Version(
                value="10.4.3",
                release_date=datetime(2020, 5, 19, 13, 16, 31, tzinfo=tzlocal()),
            ),
        }

    def test_composer_url(self):
        expected_url = "https://repo.packagist.org/p/typo3/cms-core.json"
        found_url = self.version_api.composer_url("typo3/cms-core")
        assert expected_url == found_url

    def test_extract_versions(self):

        found_versions = self.version_api.extract_versions(self.response, "typo3/cms-core")
        assert found_versions == self.expected_versions

    def test_fetch(self):

        assert self.version_api.get("typo3/cms-core") == VersionResponse()
        client_session = MockClientSession(self.response)
        asyncio.run(self.version_api.fetch("typo3/cms-core", client_session))
        assert self.version_api.cache["typo3/cms-core"] == self.expected_versions


class TestMavenVersionAPI(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.version_api = MavenVersionAPI()
        with open(os.path.join(TEST_DATA, "maven_api", "maven-metadata.xml")) as f:
            cls.response = ET.parse(f)

        with open(os.path.join(TEST_DATA, "maven_api", "maven-metadata.xml"), "rb") as f:
            cls.content = f.read()

    def test_artifact_url(self):
        eg_comps1 = ["org.apache", "kafka"]
        eg_comps2 = ["apple.msft.windows.mac.oss", "exfat-ntfs"]

        url1 = self.version_api.artifact_url(eg_comps1)
        url2 = self.version_api.artifact_url(eg_comps2)

        assert "https://repo1.maven.org/maven2/org/apache/kafka/maven-metadata.xml" == url1
        assert (
            "https://repo1.maven.org/maven2"
            "/apple/msft/windows/mac/oss/exfat-ntfs/maven-metadata.xml" == url2
        )

    def test_extract_versions(self):
        expected_versions = {Version("1.2.2"), Version("1.2.3"), Version("1.3.0")}
        assert expected_versions == self.version_api.extract_versions(self.response)

    def test_fetch(self):
        assert self.version_api.get("org.apache:kafka") == VersionResponse()
        expected = {"1.2.2", "1.2.3", "1.3.0"}
        client_session = MockClientSession(self.content)
        asyncio.run(self.version_api.fetch("org.apache:kafka", client_session))
        assert self.version_api.get("org.apache:kafka") == VersionResponse(valid_versions=expected)


class TestGoproxyVersionAPI(TestCase):
    def test_trim_url_path(self):
        url1 = "https://pkg.go.dev/github.com/containous/traefik/v2"
        url2 = "github.com/FerretDB/FerretDB/cmd/ferretdb"
        url3 = GoproxyVersionAPI.trim_url_path(url2)
        assert "github.com/containous/traefik" == GoproxyVersionAPI.trim_url_path(url1)
        assert "github.com/FerretDB/FerretDB/cmd" == url3
        assert "github.com/FerretDB/FerretDB" == GoproxyVersionAPI.trim_url_path(url3)

    def test_escape_path(self):
        path = "github.com/FerretDB/FerretDB"
        assert "github.com/!ferret!d!b/!ferret!d!b" == GoproxyVersionAPI.escape_path(path)

    def test_parse_version_info(self):
        with open(os.path.join(TEST_DATA, "goproxy_api", "version_info")) as f:
            vinfo = json.load(f)
        client_session = MockClientSession(vinfo)
        assert asyncio.run(
            GoproxyVersionAPI.parse_version_info(
                "v0.0.5", "github.com/!ferret!d!b/!ferret!d!b", client_session
            )
        ) == Version(
            value="v0.0.5",
            release_date=datetime(2022, 1, 4, 13, 54, 1, tzinfo=tzutc()),
        )

    def test_fetch(self):
        version_api = GoproxyVersionAPI()
        assert version_api.get("github.com/FerretDB/FerretDB") == VersionResponse()
        with open(os.path.join(TEST_DATA, "goproxy_api", "ferretdb_versions")) as f:
            vlist = f.read()
        client_session = MockClientSession(vlist)
        asyncio.run(version_api.fetch("github.com/FerretDB/FerretDB", client_session))
        assert version_api.cache["github.com/FerretDB/FerretDB"] == {
            Version(value="v0.0.1"),
            Version(value="v0.0.2"),
            Version(value="v0.0.3"),
            Version(value="v0.0.4"),
            Version(value="v0.0.5"),
        }


class TestNugetVersionAPI(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.version_api = NugetVersionAPI()
        with open(os.path.join(TEST_DATA, "nuget_api", "index.json")) as f:
            cls.response = json.load(f)

        cls.expected_versions = {
            Version(
                value="1.0.0",
                release_date=datetime(2018, 9, 13, 8, 16, 0, 420000, tzinfo=tzlocal()),
            ),
            Version(
                value="1.0.1",
                release_date=datetime(2020, 1, 17, 15, 31, 41, 857000, tzinfo=tzlocal()),
            ),
            Version(
                value="1.0.2",
                release_date=datetime(2020, 4, 21, 12, 24, 53, 877000, tzinfo=tzlocal()),
            ),
            Version(
                value="2.0.0-preview01",
                release_date=datetime(2018, 1, 9, 17, 12, 20, 440000, tzinfo=tzlocal()),
            ),
            Version(
                value="2.0.0",
                release_date=datetime(2018, 9, 27, 13, 33, 15, 370000, tzinfo=tzlocal()),
            ),
            Version(
                value="2.1.0",
                release_date=datetime(2018, 10, 16, 6, 59, 44, 680000, tzinfo=tzlocal()),
            ),
            Version(
                value="2.2.0",
                release_date=datetime(2018, 11, 23, 8, 13, 8, 3000, tzinfo=tzlocal()),
            ),
            Version(
                value="2.3.0",
                release_date=datetime(2019, 6, 27, 14, 27, 31, 613000, tzinfo=tzlocal()),
            ),
            Version(
                value="2.4.0",
                release_date=datetime(2020, 1, 17, 15, 11, 5, 810000, tzinfo=tzlocal()),
            ),
            Version(
                value="2.5.0",
                release_date=datetime(2020, 3, 24, 14, 22, 39, 960000, tzinfo=tzlocal()),
            ),
            Version(
                value="2.7.0",
                release_date=datetime(2020, 4, 21, 12, 27, 36, 427000, tzinfo=tzlocal()),
            ),
            Version(
                value="2.6.0",
                release_date=datetime(2020, 3, 27, 11, 6, 27, 500000, tzinfo=tzlocal()),
            ),
            Version(
                value="0.24.0",
                release_date=datetime(2018, 3, 30, 7, 25, 18, 393000, tzinfo=tzlocal()),
            ),
            Version(
                value="0.23.0",
                release_date=datetime(2018, 1, 17, 9, 32, 59, 283000, tzinfo=tzlocal()),
            ),
        }

    def test_nuget_url(self):
        expected_url = "https://api.nuget.org/v3/registration5-semver1/exfat.ntfs/index.json"
        found_url = self.version_api.nuget_url("exfat.ntfs")
        assert expected_url == found_url

    def test_extract_versions(self):

        found_versions = self.version_api.extract_versions(self.response)
        assert self.expected_versions == found_versions

    def test_fetch(self):

        assert self.version_api.get("Exfat.Ntfs") == VersionResponse()
        client_session = MockClientSession(self.response)
        asyncio.run(self.version_api.fetch("Exfat.Ntfs", client_session))
        assert self.version_api.get("Exfat.Ntfs") == VersionResponse(
            newer_versions=set(),
            valid_versions={
                "2.0.0",
                "2.1.0",
                "2.0.0-preview01",
                "0.24.0",
                "0.23.0",
                "1.0.1",
                "2.2.0",
                "2.4.0",
                "1.0.0",
                "1.0.2",
                "2.3.0",
                "2.7.0",
                "2.5.0",
                "2.6.0",
            },
        )

    # def test_load_to_api(self):
    #     assert self.version_api.get("Exfat.Ntfs") == set()

    #     mock_response = MagicMock()
    #     mock_response.json = lambda: self.response

    #     with patch("vulnerabilities.package_managers.requests.get", return_value=mock_response):
    #         self.version_api.load_to_api("Exfat.Ntfs")

    #     assert self.version_api.get("Exfat.Ntfs") == self.expected_versions


class TestGitHubTagsAPI(TestCase):
    regen = False

    def setUp(self) -> None:
        if not os.getenv("GH_TOKEN"):
            if not distutils.spawn.find_executable("svn"):
                raise SkipTest("cannot find svn executable and GH_TOKEN variable is not set")

        return super().setUp()

    def do_test_fetch(self, ownername):
        self.version_api = GitHubTagsAPI()
        test_id = ownername.replace("/", "_")

        async def async_run():
            async with RecordedClientSession(test_id, regen=self.regen) as session:
                await self.version_api.fetch(ownername, session)

        asyncio.run(async_run())

    def test_simple(self):
        self.do_test_fetch("nexB/vulnerablecode")
        assert self.version_api.get("nexB/vulnerablecode") == VersionResponse(
            newer_versions=set(),
            valid_versions={
                "v0.1",
                "v20.10",
            },
        )

    def test_huge_repo(self):
        self.do_test_fetch("torvalds/linux")
        assert len(self.version_api.get("torvalds/linux").valid_versions) > 700
