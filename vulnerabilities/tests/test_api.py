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
import os

from django.test import TestCase

from vulnerabilities.models import Package
from vulnerabilities.serializers import PackageSerializer
from vulnerabilities.data_dump import debian_dump
from vulnerabilities.data_dump import ubuntu_dump
from vulnerabilities.scraper import debian
from vulnerabilities.scraper import ubuntu


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, 'test_data/')


class TestResponse(TestCase):
    def test_debian_response(self):
        with open(os.path.join(TEST_DATA, 'debian.json')) as f:
            test_data = json.loads(f.read())

        extract_data = debian.extract_vulnerabilities(test_data)
        debian_dump(extract_data)
        response = self.client.get('/api/mimetex', format='json')

        expected = [{
            "name": "mimetex",
            "version": "1.50-1.1",
            "platform": "",
            "vulnerabilities": [{
                "summary": "Multiple stack-based buffer overflows in mimetex.cgi in mimeTeX",
                "cvss": None,
                "references": [{
                    "reference_id": "CVE-2009-2458",
                    "source": "",
                    "url": "",
                }]
            }],
            "references": [],
        }, {
            "name": "mimetex",
            "version": "1.50-1.1",
            "platform": "",
            "vulnerabilities": [{
                "summary": "Multiple unspecified vulnerabilities in mimeTeX.",
                "cvss": None,
                "references": [{
                    "reference_id": "CVE-2009-2459",
                    "source": "",
                    "url": "",
                }]
            }],
            "references": [],
        }]

        self.assertEqual(expected, response.data)

    def test_ubuntu_response(self):
        with open(os.path.join(TEST_DATA, 'ubuntu_main.html')) as f:
            test_data = f.read()

        extract_data = ubuntu.extract_cves(test_data)
        ubuntu_dump(extract_data)
        response = self.client.get('/api/automake', format='json')

        expected = [{
            "name": "automake",
            "version": "",
            "platform": "",
            "vulnerabilities": [{
                "summary": "",
                "cvss": None,
                "references": [{
                    "reference_id": "CVE-2012-3386",
                    "source": "",
                    "url": "",
                }]
            }],
            "references": [],
        }]

        self.assertEqual(expected, response.data)

    def test_blank_response(self):
        response_invalid = self.client.get('/api/', format='json')
        response_blank = self.client.get('/api/abbpcc', format='json')

        self.assertEqual(404, response_invalid.status_code)
        self.assertEqual([], response_blank.data)


class TestSerializers(TestCase):
    def test_serializers(self):
        with open(os.path.join(TEST_DATA, 'debian.json')) as f:
            test_data = json.loads(f.read())
        extract_data = debian.extract_vulnerabilities(test_data)
        debian_dump(extract_data)

        pk = Package.objects.filter(name="mimetex")
        response = PackageSerializer(pk, many=True).data

        expected = [
            {
                "name": "mimetex",
                "version": "1.50-1.1",
                "platform": "",
                "vulnerabilities": [{
                    "summary": "Multiple stack-based buffer overflows in mimetex.cgi in mimeTeX",
                    "cvss": None,
                    "references": [{
                        "reference_id": "CVE-2009-2458",
                        "source": "",
                        "url": "",
                    }]
                }],
                "references": [],
            },
            {
                "name": "mimetex",
                "version": "1.50-1.1",
                "platform": "",
                "vulnerabilities": [{
                    "summary": "Multiple unspecified vulnerabilities in mimeTeX.",
                    "cvss": None,
                    "references": [{
                        "reference_id": "CVE-2009-2459",
                        "source": "",
                        "url": "",
                    }]
                }],
                "references": [],
            }
        ]

        self.assertEqual(expected, response)
