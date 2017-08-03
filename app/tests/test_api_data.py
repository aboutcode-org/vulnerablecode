#
# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode requires an acknowledgment.
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

from vulncode_app.api_data import extract_fields


test_data = """
[{
    "Modified": "2008-11-15T00:00:00",
    "Published": "2007-02-19T21:28:00",
    "access": {
        "authentication": "NONE",
        "complexity": "MEDIUM",
        "vector": "NETWORK"
    },
    "cvss": 4.3,
    "cvss-time": "2007-02-20T14:55:00",
    "id": "CVE-2007-1004",
    "impact": {
        "availability": "NONE",
        "confidentiality": "NONE",
        "integrity": "PARTIAL"
    },
    "reason": "Link",
    "references": [
        "http://securityreason.com/securityalert/2264",
        "http://www.securityfocus.com/archive/1/archive/1/460369/100/0/threaded",
        "http://www.securityfocus.com/archive/1/archive/1/460412/100/0/threaded",
        "http://www.securityfocus.com/archive/1/archive/1/460617/100/0/threaded",
        "http://www.securityfocus.com/bid/22601",
        "http://xforce.iss.net/xforce/xfdb/32580"
    ],
    "summary": "Mozilla Firefox might allow remote",
    "vulnerable_configuration": [
        "cpe:2.3:a:mozilla:firefox:2.0:rc3"
    ],
    "vulnerable_configuration_cpe_2_2": [
        "cpe:/a:mozilla:firefox:2.0:rc3"
    ]
}]
"""


def test_extract_fields_data():
    fields_names = ['id', 'cvss', 'summary']
    data = json.loads(test_data)
    extracted_data = extract_fields(data=data, fields_names=fields_names)

    assert extracted_data == [{'cvss': 4.3, 'id': 'CVE-2007-1004',
                               'summary': 'Mozilla Firefox might allow remote'}]


def test_extract_fields():
    fields_names = []
    data = json.loads(test_data)
    extracted_data = extract_fields(data=data, fields_names=fields_names)
    assert extracted_data == [{}]

    fields_names = ['']
    extracted_data = extract_fields(data=data, fields_names=fields_names)
    assert extracted_data == [{'': None}]

    fields_names = ['invalid_field']
    extracted_data = extract_fields(data=data, fields_names=fields_names)
    assert extracted_data == [{'invalid_field': None}]
