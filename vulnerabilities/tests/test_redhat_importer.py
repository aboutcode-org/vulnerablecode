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
import unittest
from collections import OrderedDict

from packageurl import PackageURL

import vulnerabilities.importers.redhat as redhat
from vulnerabilities.data_source import Advisory

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, 'test_data/', 'redhat.json')


def load_test_data():
    with open(TEST_DATA) as f:
        return json.load(f)


class TestRedhat(unittest.TestCase):

    def test_rpm_to_purl(self):

        assert redhat.rpm_to_purl("foobar") is None
        assert redhat.rpm_to_purl("foo-bar-devel-0:sys76") is None
        assert redhat.rpm_to_purl("kernel-0:2.6.32-754.el6") == PackageURL(
            type='rpm',
            namespace='redhat',
            name='kernel',
            version='2.6.32-754.el6',
            qualifiers=OrderedDict(),
            subpath=None)

    def test_to_advisory(self):
        data = load_test_data()
        expected_data = {
            Advisory(
                summary='CVE-2016-9401 bash: popd controlled free',
                impacted_package_urls=[
                    PackageURL(
                        type='rpm',
                        namespace='redhat',
                        name='bash',
                        version='4.2.46-28.el7',
                        qualifiers=OrderedDict(),
                        subpath=None),
                    PackageURL(
                        type='rpm',
                        namespace='redhat',
                        name='bash',
                        version='4.1.2-48.el6',
                        qualifiers=OrderedDict(),
                        subpath=None)],
                resolved_package_urls=[],
                reference_urls=[
                    'https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2016-9401.json'],
                reference_ids=[
                    'RHSA-2017:1931',
                    'RHSA-2017:0725'],
                cve_id='CVE-2016-9401'),
            Advisory(
                summary=('CVE-2016-10200 kernel: l2tp: Race condition '
                         'in the L2TPv3 IP encapsulation feature'),
                impacted_package_urls=[
                    PackageURL(
                        type='rpm',
                        namespace='redhat',
                        name='kernel-rt',
                        version='3.10.0-693.rt56.617.el7',
                        qualifiers=OrderedDict(),
                        subpath=None),
                    PackageURL(
                        type='rpm',
                        namespace='redhat',
                        name='kernel',
                        version='3.10.0-693.el7',
                        qualifiers=OrderedDict(),
                        subpath=None),
                    PackageURL(
                        type='rpm',
                        namespace='redhat',
                        name='kernel',
                        version='3.10.0-514.28.1.el7',
                        qualifiers=OrderedDict(),
                        subpath=None)],
                resolved_package_urls=[],
                reference_urls=[
                    'https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2016-10200.json'],
                reference_ids=[
                    'RHSA-2017:1842',
                    'RHSA-2017:2437',
                    'RHSA-2017:2077',
                    'RHSA-2017:2444'],
                cve_id='CVE-2016-10200'),
            Advisory(
                summary=('CVE-2017-12168 Kernel: kvm: ARM64: '
                         'assert failure when accessing PMCCNTR register'),
                impacted_package_urls=[],
                resolved_package_urls=[],
                reference_urls=[
                    'https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2017-12168.json'],
                reference_ids=[],
                cve_id='CVE-2017-12168'),
        }

        found_data = set()
        for adv in data:
            found_data.add(redhat.to_advisory(adv))
        assert expected_data == found_data
