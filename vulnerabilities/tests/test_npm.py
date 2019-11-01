# Author: Navonil Das (@NavonilDas)
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
import json

from django.test import TestCase

from vulnerabilities.scraper.npm import extract_data
from vulnerabilities.scraper.npm import get_all_versions
from vulnerabilities.scraper.npm import remove_spaces

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, 'test_data/')


class NPMScrapperTest(TestCase):
    def test_remove_space(self):
        res = remove_spaces(">=    1.2.1     ||    <= 2.1.1")
        self.assertEqual(res, '>=1.2.1 || <=2.1.1')

        res = remove_spaces(">=    v1.2.1     ||    <= V2.1.1")
        self.assertEqual(res, '>=1.2.1 || <=2.1.1')

    def test_get_all_versions(self):
        x = get_all_versions('electron')
        expected = ['0.1.2', '2.0.0', '3.0.0',
                    '4.0.0', '5.0.0', '6.0.0', '7.0.0']
        self.assertTrue(set(expected) <= set(x))

    def test_extract_data(self):
        with open(os.path.join(TEST_DATA, 'npm_test.json')) as f:
            test_data = json.load(f)

        expected = {
            'package_name': 'hapi',
            'cve_ids': ['CVE-2014-4671'],
            'fixed_versions': [
                '6.1.0', '6.2.0', '6.2.1', '6.2.2', '6.3.0', '6.4.0',
                '6.5.0', '6.5.1', '6.6.0', '6.7.0', '6.7.1', '6.8.0',
                '6.8.1', '6.9.0', '6.10.0', '6.11.0', '6.11.1', '7.0.0',
                '7.0.1', '7.1.0', '7.1.1', '7.2.0', '7.3.0', '7.4.0',
                '7.5.0', '7.5.1', '7.5.2', '8.0.0', '7.5.3', '8.1.0',
                '8.2.0', '8.3.0', '8.3.1', '8.4.0', '8.5.0', '8.5.1',
                '8.5.2', '8.5.3', '8.6.0', '8.6.1', '8.8.0', '8.8.1',
                '9.0.0', '9.0.1', '9.0.2', '9.0.3', '9.0.4', '9.1.0',
                '9.2.0', '9.3.0', '9.3.1', '10.0.0', '10.0.1', '10.1.0',
                '10.2.1', '10.4.0', '10.4.1', '10.5.0', '11.0.0', '11.0.1',
                '11.0.2', '11.0.3', '11.0.4', '11.0.5', '11.1.0', '11.1.1',
                '11.1.2', '11.1.3', '11.1.4', '12.0.0', '12.0.1', '12.1.0',
                '9.5.1', '13.0.0', '13.1.0', '13.2.0', '13.2.1', '13.2.2',
                '13.3.0', '13.4.0', '13.4.1', '13.4.2', '13.5.0', '14.0.0',
                '13.5.3', '14.1.0', '14.2.0', '15.0.1', '15.0.2', '15.0.3',
                '15.1.0', '15.1.1', '15.2.0', '16.0.0', '16.0.1', '16.0.2',
                '16.0.3', '16.1.0', '16.1.1', '16.2.0', '16.3.0', '16.3.1',
                '16.4.0', '16.4.1', '16.4.2', '16.4.3', '16.5.0', '16.5.1',
                '16.5.2', '16.6.0', '16.6.1', '16.6.2', '17.0.0', '17.0.1',
                '17.0.2', '17.1.0', '17.1.1', '17.2.0', '17.2.1', '16.6.3',
                '17.2.2', '17.2.3', '17.3.0', '17.3.1', '17.4.0', '17.5.0',
                '17.5.1', '17.5.2', '17.5.3', '17.5.4', '17.5.5', '17.6.0',
                '17.6.1', '17.6.2', '17.6.3', '16.6.4', '17.6.4', '16.6.5',
                '17.7.0', '16.7.0', '17.8.0', '17.8.1', '18.0.0', '17.8.2',
                '17.8.3', '18.0.1', '17.8.4', '18.1.0', '17.8.5'],
            'affected_versions': [
                '0.0.1', '0.0.2', '0.0.3', '0.0.4', '0.0.5', '0.0.6', '0.1.0',
                '0.1.1', '0.1.2', '0.1.3', '0.2.0', '0.2.1', '0.3.0', '0.4.0',
                '0.4.1', '0.4.2', '0.4.3', '0.4.4', '0.5.0', '0.5.1', '0.6.0',
                '0.6.1', '0.5.2', '0.7.0', '0.7.1', '0.8.0', '0.8.1', '0.8.2',
                '0.8.3', '0.8.4', '0.9.0', '0.9.1', '0.9.2', '0.10.0', '0.10.1',
                '0.11.0', '0.11.1', '0.11.2', '0.11.3', '0.12.0', '0.13.0',
                '0.13.1', '0.13.2', '0.11.4', '0.13.3', '0.14.0', '0.14.1',
                '0.14.2', '0.15.0', '0.15.1', '0.15.2', '0.15.3', '0.15.4',
                '0.15.5', '0.15.6', '0.15.7', '0.15.8', '0.15.9', '0.16.0',
                '1.0.0', '1.0.1', '1.0.2', '1.0.3', '1.1.0', '1.2.0', '1.3.0',
                '1.4.0', '1.5.0', '1.6.0', '1.6.1', '1.6.2', '1.7.0', '1.7.1',
                '1.7.2', '1.7.3', '1.8.0', '1.8.1', '1.8.2', '1.8.3', '1.9.0',
                '1.9.1', '1.9.2', '1.9.3', '1.9.4', '1.9.5', '1.9.6', '1.9.7',
                '1.10.0', '1.11.0', '1.11.1', '1.12.0', '1.13.0', '1.14.0',
                '1.15.0', '1.16.0', '1.16.1', '1.17.0', '1.18.0', '1.19.0',
                '1.19.1', '1.19.2', '1.19.3', '1.19.4', '1.19.5', '1.20.0',
                '2.0.0', '2.1.0', '2.1.1', '2.1.2', '2.2.0', '2.3.0', '2.4.0',
                '2.5.0', '2.6.0', '3.0.0', '3.0.1', '3.0.2', '3.1.0', '4.0.0',
                '4.0.1', '4.0.2', '4.0.3', '4.1.0', '4.1.1', '4.1.2', '4.1.3',
                '4.1.4', '5.0.0', '5.1.0', '6.0.0', '6.0.1', '6.0.2'],
            'severity': 'moderate'
        }
        got = extract_data(test_data)[0]
        # Check if expected affected version and fixed version is subset of what we get from online
        self.assertTrue(set(expected['fixed_versions'])
                        <= set(got['fixed_versions']))
        self.assertTrue(set(expected['affected_versions']) <= set(
            got['affected_versions']))

        self.assertEqual(expected['package_name'], got['package_name'])
        self.assertEqual(expected['severity'], got['severity'])
        self.assertEqual(expected['cve_ids'], got['cve_ids'])
