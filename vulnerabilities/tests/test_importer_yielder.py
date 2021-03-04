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

from unittest import TestCase
from unittest.mock import patch

import pytest

from vulnerabilities import importer_yielder
from vulnerabilities.models import Importer

MOCK_IMPORTER_REGISTRY = [
    {
        "name": "mock_rust",
        "license": "https://creativecommons.org/publicdomain/zero/1.0/",
        "last_run": None,
        "data_source": "RustDataSource",
        "data_source_cfg": {
            "branch": None,
            "repository_url": "https://github.com/RustSec/advisory-db",
        },
    },
    {
        "name": "mock_alpine",
        "license": "",
        "last_run": None,
        "data_source": "AlpineDataSource",
        "data_source_cfg": {
            "branch": None,
            "repository_url": "https://gitlab.alpinelinux.org/alpine/infra/alpine-secdb",
            "etags": {},
        },
    },
]


class TestImporterYielder(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.importer_yielder = importer_yielder

    @pytest.mark.django_db
    def test_load_importers_freshdb(self):
        assert Importer.objects.all().count() == 0

        with patch(
            "vulnerabilities.importer_yielder.IMPORTER_REGISTRY", new=MOCK_IMPORTER_REGISTRY
        ):  # nopep8
            self.importer_yielder.load_importers()
            assert Importer.objects.all().count() == 2

    @pytest.mark.django_db
    def test_load_importers_setteddb(self):
        assert Importer.objects.all().count() == 0

        mock_existing_importer = Importer.objects.create(**MOCK_IMPORTER_REGISTRY[1])
        mock_existing_importer.data_source_cfg["etags"] = {"url": "0x1234"}
        mock_existing_importer.save()

        assert Importer.objects.all().count() == 1

        with patch(
            "vulnerabilities.importer_yielder.IMPORTER_REGISTRY", new=MOCK_IMPORTER_REGISTRY
        ):  # nopep8
            self.importer_yielder.load_importers()
            assert Importer.objects.all().count() == 2

        assert mock_existing_importer == Importer.objects.get(name="mock_alpine")
