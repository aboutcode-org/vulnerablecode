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
from vulncode_app.data_dump import ubuntu_dump

import json

from scraper import debian, ubuntu


class TestDataDump(TestCase):
    def test_debian_data_dump(self):
        """
        Scrape data from Debian' main tracker, save it
        in the database and verify entries.
        """
        with open("tests/test_data/debian.json") as f:
            test_data = json.loads(f.read())

        extract_data = debian.extract_data(test_data)
        data_dump = debian_dump(extract_data)

        self.assertEqual(3, Vulnerability.objects.count())
        self.assertEqual(3, VulnerabilityReference.objects.count())
        self.assertEqual(3, Package.objects.count())

        vulnerability = Vulnerability.objects.get(pk=1)
        self.assertEqual('Multiple stack-based buffer overflows in mimetex.cgi in mimeTeX',
                         vulnerability.summary)

        vulnerability = Vulnerability.objects.get(pk=2)
        self.assertEqual('Multiple unspecified vulnerabilities in mimeTeX.',
                         vulnerability.summary)

        vulnerability = Vulnerability.objects.get(pk=3)
        self.assertEqual(None, vulnerability.summary)

        vulnerability_reference = VulnerabilityReference.objects.get(pk=1)
        self.assertEqual("CVE-2009-2458", vulnerability_reference.reference_id)

        vulnerability_reference = VulnerabilityReference.objects.get(pk=2)
        self.assertEqual("CVE-2009-2459", vulnerability_reference.reference_id)

        vulnerability_reference = VulnerabilityReference.objects.get(pk=3)
        self.assertEqual("TEMP-0807341-84E914", vulnerability_reference.reference_id)

        package = Package.objects.get(pk=1)
        self.assertEqual("mimetex", package.name)

        package = Package.objects.get(pk=3)
        self.assertEqual("git-repair", package.name)

        package = Package.objects.get(pk=1)
        self.assertEqual("1.50-1.1", package.version)

        package = Package.objects.get(pk=3)
        self.assertEqual(None, package.version)

    def test_ubuntu_data_dump(self):
        """
        Scrape data from Ubuntu' main tracker, save it
        in the database and verify entries.
        """
        with open("tests/test_data/ubuntu_main.html") as f:
            test_data = f.read()

        data = ubuntu.extract_cves(test_data)
        data_dump = ubuntu_dump(data)

        vuln_reference = VulnerabilityReference.objects.get(pk=1)
        self.assertEqual("CVE-2002-2439", vuln_reference.reference_id)

        package = Package.objects.get(pk=1)
        self.assertEqual("gcc-4.6", package.name)
