# Author: Islam ElHakmi (@EslamHiko)
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
from vulnerabilities.scraper.ruby import load_vulnerability_package
import saneyaml

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, 'test_data/')


@pytest.mark.webtest
def test_extract_data():
    vulnerability = saneyaml.load(open(os.path.join(TEST_DATA, 'ruby.yml')))
    package = load_vulnerability_package(vulnerability)
    expected = {
        'package_name': 'actionpack',
        'cve_id': 'CVE-2016-0751',
        'fixed_versions': {
            '5.2.1.1', '5.0.4', '5.2.0.beta2', '4.2.8.rc1',
            '3.2.22.3', '4.2.7', '5.1.7', '5.1.2.rc1', '3.2.22.5',
            '4.2.11', '5.0.7.2', '4.1.14.1', '5.0.7', '5.0.3', '4.2.8',
            '5.0.2', '4.2.6', '6.0.0.beta2', '5.0.0.rc1',
            '5.2.4.1', '5.0.6.rc1', '4.2.10.rc1', '3.2.22.2', '5.2.3',
            '4.2.10', '5.1.0.rc1', '6.0.1.rc1', '3.2.22',
            '4.1.15.rc1', '5.2.0.beta1', '5.1.0.rc2', '5.0.2.rc1',
            '5.1.0.beta1', '6.0.2.rc1', '3.2.22.4', '6.0.0.rc2',
            '5.0.0.racecar1', '5.2.4.2', '5.0.1', '5.2.0.rc1', '6.0.0',
            '5.0.1.rc1', '5.1.4', '4.2.5.1', '5.0.1.rc2',
            '5.1.5.rc1', '5.0.5.rc1', '5.2.0', '5.0.7.1', '6.0.2.2',
            '4.2.9', '5.0.0.beta1.1', '4.2.7.rc1', '5.1.0',
            '5.2.2', '5.2.3.rc1', '5.1.3.rc3', '5.2.1.rc1', '4.2.9.rc2',
            '5.1.3.rc2', '4.2.7.1', '5.0.0.1', '5.0.4.rc1',
            '5.0.5', '6.0.2.1', '5.0.6', '5.1.3', '6.0.1', '5.1.5',
            '5.0.0.rc2', '5.2.1', '4.1.16.rc1', '5.0.0', '6.0.0.beta1',
            '5.2.4', '6.0.2', '5.1.2', '5.1.6.2', '5.1.1', '3.2.22.1',
            '4.2.6.rc1', '4.1.15', '4.2.5.2', '5.2.0.rc2', '4.1.14.2',
            '5.1.3.rc1', '5.1.7.rc1', '6.0.0.rc1', '4.2.11.1', '5.2.2.rc1',
            '5.0.5.rc2', '5.2.4.rc1', '5.1.6.1', '4.1.16', '5.1.4.rc1',
            '4.2.9.rc1', '6.0.2.rc2', '5.1.6', '5.2.2.1', '6.0.0.beta3'
        },
        'affected_versions': {
            '4.1.0', '4.1.10.rc2', '2.0.5', '2.3.17', '3.2.12',
            '4.2.5.rc1', '4.2.3', '3.2.13', '4.0.6.rc3',
            '2.3.4', '1.13.4', '3.0.10.rc1', '4.1.11', '3.1.0',
            '3.2.0', '4.0.1.rc3', '3.0.16', '3.0.2', '0.9.0', '3.2.13.rc1',
            '3.1.7', '4.0.1.rc2', '4.0.6.rc1', '4.1.10.rc1', '2.1.1',
            '3.2.14', '2.3.8.pre1', '1.13.2', '2.0.4', '3.1.0.beta1',
            '3.1.2.rc2', '3.0.14', '3.2.8', '3.1.12', '1.3.1', '4.2.1.rc3',
            '4.1.8', '3.0.15', '3.1.2.rc1', '4.0.1', '3.1.6',
            '5.0.0.beta2', '2.1.0', '4.0.0.rc1', '4.0.7', '3.2.10',
            '4.1.7.1', '4.1.2.rc3', '5.0.0.beta3', '3.2.15', '2.3.10',
            '4.1.10.rc3', '4.1.1', '3.2.20', '4.2.5.rc2', '1.3.0',
            '4.1.4', '3.0.5.rc1', '4.0.1.rc1', '4.1.0.rc1', '3.2.2.rc1',
            '2.3.8', '4.1.0.beta1', '3.0.0.beta', '4.0.8', '2.0.1',
            '1.5.1', '4.0.2', '4.1.3', '3.0.18', '1.10.2', '3.0.8.rc2',
            '3.0.9.rc3', '1.8.0', '1.12.3', '4.0.10.rc1', '3.1.8',
            '1.9.0', '4.2.4', '1.13.3', '4.1.2.rc1', '3.2.21', '4.0.11.1',
            '3.0.0.beta4', '4.2.1.rc4', '4.1.12', '2.2.3', '4.2.3.rc1',
            '3.0.5', '4.1.13', '2.3.9.pre', '3.0.6.rc2', '4.1.0.rc2',
            '3.2.16', '3.2.3.rc1', '3.0.11', '0.9.5', '3.2.8.rc1', '3.2.3',
            '4.0.12', '4.1.12.rc1', '3.1.1.rc3', '3.2.15.rc3', '3.0.6',
            '4.1.0.beta2', '4.1.7', '4.2.0', '4.1.9', '3.2.9.rc2', '2.0.2',
            '4.1.10', '4.0.1.rc4', '3.0.13', '4.1.2', '2.2.2', '4.2.4.rc1',
            '3.0.9.rc1', '3.1.0.rc5', '4.1.5', '3.2.0.rc1', '4.0.0.beta1',
            '3.0.8', '1.7.0', '3.0.9.rc4', '3.2.15.rc2', '4.2.0.rc3', '3.2.8.rc2',
            '1.4.0', '2.3.16', '2.3.3', '3.1.5.rc1', '3.2.9', '1.0.0',
            '4.2.0.beta4', '3.0.4', '3.0.7.rc1', '3.1.10', '1.10.1', '1.8.1', '2.3.11',
            '3.1.0.rc4', '4.1.6', '5.0.0.beta1', '1.12.0', '1.12.4',
            '2.3.6', '3.0.0.beta3', '3.2.17', '3.2.11', '4.1.14.rc2', '3.1.4.rc1', '4.1.14',
            '3.0.3', '1.2.0', '4.0.4', '1.13.6', '1.9.1', '5.0.0.beta4',
            '3.0.17', '3.0.19', '4.0.13.rc1', '2.3.18', '1.13.0', '2.3.7', '3.2.2',
            '3.2.6', '4.0.10', '2.3.14', '4.0.13', '2.3.2', '3.0.9',
            '3.1.5', '4.2.1.rc1', '4.2.0.rc1', '4.2.0.rc2', '3.1.11', '3.0.12', '3.2.14.rc2',
            '3.0.0', '4.2.5', '3.0.13.rc1', '1.1.0', '4.1.10.rc4',
            '3.2.18', '4.1.6.rc2', '3.0.6.rc1', '3.2.1', '3.0.9.rc5', '1.11.2', '4.0.6.rc2',
            '3.0.10', '3.1.3', '4.0.6', '3.0.8.rc1', '3.1.2', '2.1.2',
            '3.2.9.rc3', '3.2.4.rc1', '3.0.8.rc4', '3.0.4.rc1', '1.12.5', '3.0.1', '3.2.7.rc1',
            '4.0.11', '3.0.12.rc1', '4.0.10.rc2', '3.1.1.rc2', '3.2.7',
            '1.11.1', '2.3.15', '3.2.19', '3.1.9', '2.3.9', '4.1.9.rc1', '4.0.4.rc1',
            '4.1.13.rc1', '4.2.1', '3.1.0.rc2', '1.12.1', '4.0.9',
            '1.12.2', '3.1.0.rc1', '1.13.5', '1.6.0', '2.3.12', '4.2.1.rc2',
            '4.0.0', '3.2.13.rc2', '3.0.0.beta2', '3.2.3.rc2', '3.2.4',
            '3.2.14.rc1', '3.2.9.rc1', '4.0.0.rc2', '3.1.4', '3.0.20',
            '1.11.0', '1.0.1', '3.2.5', '4.2.0.beta1', '3.0.7', '3.1.1',
            '2.0.0', '4.2.0.beta3', '3.1.0.rc8', '4.0.3', '2.3.5',
            '3.1.0.rc3', '3.1.1.rc1', '4.0.5', '1.5.0', '3.0.7.rc2',
            '4.2.0.beta2', '1.13.1', '4.1.2.rc2', '3.0.0.rc2', '3.0.0.rc',
            '3.1.0.rc6', '4.1.14.rc1', '4.2.2', '3.2.0.rc2', '4.1.6.rc1', '3.2.15.rc1'
        },
        'advisory': 'https://groups.google.com/forum/#!topic/rubyonrails-security/9oLY_FCzvoc'
    }
    assert expected['package_name'] == package['package_name']
    assert expected['cve_id'] == package['cve_id']
    assert expected['advisory'] == package['advisory']
    # Check if expected affected version and fixed version is subset of what we get from online
    assert set(expected['fixed_versions']) <= set(package['fixed_versions'])
    assert set(expected['affected_versions']) <= set(
        package['affected_versions'])
