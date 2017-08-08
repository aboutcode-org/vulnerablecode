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

import json
from os.path import dirname
from os.path import join

from scraper import debian
from scraper import ubuntu


def test_ubuntu_extract_cves():
    ubuntu_testfile = join(dirname(__file__), 'test_data', 'ubuntu_main.html')

    with open(ubuntu_testfile) as f:
        test_input = f.read()

    cves = ubuntu.extract_cves(test_input)

    expected = {
        'cve_id': 'CVE-2002-2439',
        'package_name': 'gcc-4.6',
        'vulnerability_status': 'low'
    }
    assert expected == cves[0]

    expected = {
        'cve_id': 'CVE-2013-0157',
        'package_name': 'util-linux',
        'vulnerability_status': 'low',
    }
    assert expected == cves[50]

    expected = {
        'cve_id': 'CVE-2017-9986',
        'package_name': 'linux-lts-xenial',
        'vulnerability_status': 'medium',
    }
    assert expected == cves[-1]


def test_debian_extract_vulnerabilities():
    debian_test_file = join(dirname(__file__), 'test_data', 'debian.json')

    with open(debian_test_file) as f:
        test_data = json.loads(f.read())

    expected = [
        {
            'fixed_version': '1.50-1.1',
            'package_name': 'mimetex',
            'status': 'resolved',
            'urgency': 'medium',
            'vulnerability_id': 'CVE-2009-2458',
            'description': 'Multiple stack-based buffer overflows in mimetex.cgi in mimeTeX'
        },
        {
            'fixed_version': '1.50-1.1',
            'package_name': 'mimetex',
            'status': 'not-resolved',
            'urgency': 'medium',
            'vulnerability_id': 'CVE-2009-2459',
            'description': 'Multiple unspecified vulnerabilities in mimeTeX.'
        },
        {
            'package_name': 'git-repair',
            'vulnerability_id': 'TEMP-0807341-84E914',
            'description': '',
            'status': 'open',
            'urgency': 'unimportant',
            'fixed_version': ''
        }
    ]

    assert expected == debian.extract_vulnerabilities(test_data)
