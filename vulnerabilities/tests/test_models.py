# Copyright (c) nexB Inc. and others. All rights reserved.
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
#  VulnerableCode is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

from datetime import datetime
from unittest import TestCase
from unittest.mock import MagicMock, patch

import pytest
from freezegun import freeze_time

from vulnerabilities import models


class TestVulnerabilityModel(TestCase):

    def test_generate_vulcoid_given_timestamp_object(self):
        timestamp_object = datetime(2021, 1, 1, 11, 12, 13)
        expected_vulcoid = "VULCOID-2021-01-01111213"
        found_vulcoid = models.Vulnerability.generate_vulcoid(timestamp_object)
        assert expected_vulcoid == found_vulcoid

    def test_generate_vulcoid(self):
        expected_vulcoid = "VULCOID-2021-01-01111213"
        with freeze_time("2021-01-01 11:12:13"):
            found_vulcoid = models.Vulnerability.generate_vulcoid()
        assert expected_vulcoid == found_vulcoid

    @pytest.mark.django_db
    def test_vulnerability_save_with_vulnerability_id(self):
        models.Vulnerability(vulnerability_id="CVE-2020-7965").save()
        assert models.Vulnerability.objects.filter(vulnerability_id="CVE-2020-7965").count() == 1

    @pytest.mark.django_db
    def test_vulnerability_save_without_vulnerability_id(self):
        assert models.Vulnerability.objects.filter(
            vulnerability_id="VULCOID-2021-01-01111213"
            ).count() == 0

        with freeze_time("2021-01-01 11:12:13"):
            models.Vulnerability(vulnerability_id="").save()
            assert models.Vulnerability.objects.filter(
                vulnerability_id="VULCOID-2021-01-01111213"
                ).count() == 1

        assert models.Vulnerability.objects.filter(
            vulnerability_id="VULCOID-2021-01-01111214"
            ).count() == 0

        with freeze_time("2021-01-01 11:12:13", tick=True):
            # This context manager sets time to "2021-01-01 11:12:13" and starts the clock.
            models.Vulnerability(vulnerability_id="").save()
            assert models.Vulnerability.objects.filter(
                vulnerability_id="VULCOID-2021-01-01111214"
                ).count() == 1
