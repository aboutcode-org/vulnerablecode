# Copyright (c) nexB Inc. and others. All rights reserved.
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
#  VulnerableCode is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import dataclasses
from unittest import TestCase
from unittest.mock import patch
from unittest.mock import MagicMock

from vulnerabilities.data_source import DataSource
from vulnerabilities.helpers import create_etag


@dataclasses.dataclass
class DummyDataSourceConfiguration:
    etags: dict


class DummyDataSource(DataSource):
    CONFIG_CLASS = DummyDataSourceConfiguration


class TestHelpers(TestCase):
    @classmethod
    def setUpClass(cls):
        data_source_cfg = {"etags": {}}
        cls.data_source = DummyDataSource(config=data_source_cfg)

    def test_create_etag(self):
        assert self.data_source.config.etags == {}

        mock_response = MagicMock()
        mock_response.headers = {"ETag": "0x1234"}

        with patch("vulnerabilities.helpers.requests.head", return_value=mock_response):
            assert (
                create_etag(data_src=self.data_source, url="https://example.org", etag_key="ETag")
                is True
            )
            assert self.data_source.config.etags == {"https://example.org": "0x1234"}
            assert (
                create_etag(data_src=self.data_source, url="https://example.org", etag_key="ETag")
                is False
            )
