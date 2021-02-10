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

from collections import OrderedDict
import os
from unittest import TestCase
import yaml

from packageurl import PackageURL

from vulnerabilities.importers.suse_backports import SUSEBackportsDataSource
from vulnerabilities.data_source import Advisory

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def yaml_loader():
    path = os.path.join(BASE_DIR, "test_data/suse_backports/")
    yaml_files = {}
    for file in os.listdir(path):
        with open(os.path.join(path, file)) as f:
            yaml_files[file] = yaml.safe_load(f)
    return yaml_files


class TestSUSEBackportsDataSource(TestCase):

    @classmethod
    def setUpClass(cls):
        data_source_cfg = {
            'url': 'https://endpoint.com',
            'etags': {}}
        cls.data_src = SUSEBackportsDataSource(1, config=data_source_cfg)

    def test_process_file(self):
        parsed_yamls = yaml_loader()
        expected_data = [
            Advisory(
                summary='',
                impacted_package_urls=[],
                resolved_package_urls=[
                    PackageURL(
                        type='rpm',
                        namespace='opensuse',
                        name='MozillaFirefox',
                        version='3.0.10-1.1.1',
                        qualifiers=OrderedDict(),
                        subpath=None)],
                vulnerability_id='CVE-2009-1313'),
            Advisory(
                summary='',
                impacted_package_urls=[],
                resolved_package_urls=[
                        PackageURL(
                            type='rpm',
                            namespace='opensuse',
                            name='MozillaFirefox-branding-SLED',
                            version='3.5-1.1.5',
                            qualifiers=OrderedDict(),
                            subpath=None)],
                vulnerability_id='CVE-2009-1313'),
            Advisory(
                summary='',
                impacted_package_urls=[],
                resolved_package_urls=[
                    PackageURL(
                        type='rpm',
                        namespace='opensuse',
                        name='MozillaFirefox-translations',
                        version='3.0.10-1.1.1',
                        qualifiers=OrderedDict(),
                        subpath=None)],
                vulnerability_id='CVE-2009-1313'),
            Advisory(
                summary='',
                impacted_package_urls=[],
                resolved_package_urls=[
                    PackageURL(
                        type='rpm',
                        namespace='opensuse',
                        name='NetworkManager',
                        version='0.7.0.r4359-15.9.2',
                        qualifiers=OrderedDict(),
                        subpath=None)],
                vulnerability_id='CVE-2009-0365'),
            Advisory(
                summary='',
                impacted_package_urls=[],
                resolved_package_urls=[
                    PackageURL(
                        type='rpm',
                        namespace='opensuse',
                        name='NetworkManager',
                        version='0.7.0.r4359-15.9.2',
                        qualifiers=OrderedDict(),
                        subpath=None)],
                vulnerability_id='CVE-2009-0578'),
        ]

        found_data = self.data_src.process_file(
            parsed_yamls['backports-sle11-sp0.yaml'])
        assert expected_data == found_data
