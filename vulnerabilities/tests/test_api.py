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
import pytest

from django.test import Client

from vulnerabilities.api import PackageSerializer
from vulnerabilities.data_dump import debian_dump
from vulnerabilities.data_dump import ubuntu_dump
from vulnerabilities.models import Package
from vulnerabilities.scraper import debian
from vulnerabilities.scraper import ubuntu


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, 'test_data/')


def test_debian_query_by_name(setDebianData):

    client = Client()
    response = client.get('/api/packages/?name=mimetex', format='json').data
    assert 4 == response['count']
    first_result = response['results'][0]
    assert 'mimetex' == first_result['name']
    versions = {r['version'] for r in response['results']}
    assert '1.50-1.1' in versions
    assert '1.74-1' in versions

    purls = {r['package_url'] for r in response['results']}
    assert 'pkg:deb/debian/mimetex@1.50-1.1?distro=jessie' in purls
    assert 'pkg:deb/debian/mimetex@1.74-1?distro=jessie' in purls


def test_debian_query_by_invalid_package_url(setDebianData):
    client = Client()
    url = '/api/packages/?package_url=invalid_purl'
    response = client.get(url, format='json')

    assert 400 == response.status_code
    assert 'error' in response.data
    error = response.data['error']
    assert 'invalid_purl' in error


def test_debian_query_by_package_url(setDebianData):
    client = Client()
    url = '/api/packages/?package_url=pkg:deb/debian/mimetex@1.50-1.1?distro=jessie'
    response = client.get(url, format='json').data

    assert 2 == response['count']

    first_result = response['results'][0]
    assert 'mimetex' == first_result['name']
    versions = {r['version'] for r in response['results']}
    assert '1.50-1.1' in versions
    assert '1.74-1' not in versions


def test_debian_query_by_package_url_without_namespace(setDebianData):

    Package.objects.create(
            name='mimetex',
            version='1.50-1.1',
            type='deb',
            namespace='ubuntu'
        )
    client = Client()
    url = '/api/packages/?package_url=pkg:deb/mimetex@1.50-1.1'
    response = client.get(url, format='json').data

    assert 3 == response['count']

    first_result = response['results'][0]
    assert 'mimetex' == first_result['name']

    purls = {r['package_url'] for r in response['results']}
    assert 'pkg:deb/debian/mimetex@1.50-1.1?distro=jessie' in purls
    assert 'pkg:deb/ubuntu/mimetex@1.50-1.1' in purls


def test_debian_package_serializer(setDebianData):
    client = Client()
    pk = Package.objects.filter(name="mimetex")
    response = PackageSerializer(pk, many=True).data
    print(response)
    assert 4 == len(response)

    first_result = response[0]
    assert 'mimetex' == first_result['name']

    versions = {r['version'] for r in response}
    assert '1.50-1.1' in versions
    assert '1.74-1' in versions

    purls = {r['package_url'] for r in response}
    assert 'pkg:deb/debian/mimetex@1.50-1.1?distro=jessie' in purls
    assert 'pkg:deb/debian/mimetex@1.74-1?distro=jessie' in purls


def test_ubuntu_response(setUbuntuData):
    client = Client()
    response = client.get('/api/packages/?name=automake', format='json')
    result = response.data.get('results')[0]
    assert 'automake' == result['name']
    assert result['version'] is None
    assert 1 == len(result['vulnerabilities'])
    vuln = result['vulnerabilities'][0]
    assert 0 == len(vuln['references'])
