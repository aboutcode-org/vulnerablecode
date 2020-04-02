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
from vulnerabilities.scraper.ruby import rubygem_advisories
from vulnerabilities.scraper.ruby import load_vulnerability_package

RUBYSEC_DB_URL = 'https://github.com/rubysec/ruby-advisory-db/archive/master.zip'


@pytest.mark.webtest
def test_extract_data():
    for vulnerability in rubygem_advisories(RUBYSEC_DB_URL):
        package = load_vulnerability_package(vulnerability)
        assert len(package['package_name']) != 0
        assert len(package['cve_id']) != 0
        assert len(package['affected_versions']) != 0
        assert len(package['advisory']) != 0
        break
