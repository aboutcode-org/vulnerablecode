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

from django.test import TestCase

from vulncode_app.models import Vulnerability
from vulncode_app.models import VulnerabilityReference
from vulncode_app.models import Package
from vulncode_app.data_dump import debian_dump

import json

from scraper import debian


class TestDataDump(TestCase):
    def test_data_dump(self):
        """
        Scrape data from Debian' main tracker, dump it
        in the database and verify entries.
        """
        with open("tests/test_data/debian.json") as f:
            test_data = json.loads(f.read())

        extract_data = debian.extract_data(test_data)
        data_dump = debian_dump(extract_data)

        for i in range(3):
            self.assertEqual(3, len(Vulnerability.objects.all()))
            self.assertEqual(3, len(VulnerabilityReference.objects.all()))
            self.assertEqual(3, len(Package.objects.all()))
            self.assertEqual(extract_data[i].get('description'),
                             Vulnerability.objects.get(pk=i+1).summary)
            self.assertEqual(extract_data[i].get('vulnerability_id'),
                             VulnerabilityReference.objects.get(pk=i+1).reference_id)
            self.assertEqual(extract_data[i].get('package_name'),
                             Package.objects.get(pk=i+1).name)
            self.assertEqual(extract_data[i].get('fixed_version'),
                             Package.objects.get(pk=i+1).version)
