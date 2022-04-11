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

import os
from collections import OrderedDict
from unittest import TestCase

from packageurl import PackageURL

from vulnerabilities.helpers import AffectedPackage
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Reference
from vulnerabilities.importers.elixir_security import ElixirSecurityImporter
from vulnerabilities.package_managers import HexVersionAPI
from vulnerabilities.package_managers import Version

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class TestElixirSecurityImporter(TestCase):
    @classmethod
    def setUpClass(cls):
        data_source_cfg = {
            "repository_url": "https://github.com/dependabot/elixir-security-advisories",
        }
        cls.data_src = ElixirSecurityImporter(1, config=data_source_cfg)
        cls.data_src.pkg_manager_api = HexVersionAPI(
            {
                "coherence": [
                    Version("0.5.2"),
                    Version("0.5.1"),
                    Version("0.5.0"),
                    Version("0.4.0"),
                    Version("0.3.1"),
                    Version("0.3.0"),
                    Version("0.2.0"),
                    Version("0.1.3"),
                    Version("0.1.2"),
                    Version("0.1.1"),
                    Version("0.1.0"),
                ]
            }
        )

    def test_process_file(self):

        path = os.path.join(BASE_DIR, "test_data/elixir_security/test_file.yml")
        expected_advisory = Advisory(
            summary=('The Coherence library has "Mass Assignment"-like vulnerabilities.\n'),
            affected_packages=[
                AffectedPackage(
                    vulnerable_package=PackageURL(
                        type="hex",
                        namespace=None,
                        name="coherence",
                        version="0.1.0",
                        qualifiers={},
                        subpath=None,
                    ),
                    patched_package=PackageURL(
                        type="hex",
                        namespace=None,
                        name="coherence",
                        version="0.5.2",
                        qualifiers={},
                        subpath=None,
                    ),
                ),
                AffectedPackage(
                    vulnerable_package=PackageURL(
                        type="hex",
                        namespace=None,
                        name="coherence",
                        version="0.1.1",
                        qualifiers={},
                        subpath=None,
                    ),
                    patched_package=PackageURL(
                        type="hex",
                        namespace=None,
                        name="coherence",
                        version="0.5.2",
                        qualifiers={},
                        subpath=None,
                    ),
                ),
                AffectedPackage(
                    vulnerable_package=PackageURL(
                        type="hex",
                        namespace=None,
                        name="coherence",
                        version="0.1.2",
                        qualifiers={},
                        subpath=None,
                    ),
                    patched_package=PackageURL(
                        type="hex",
                        namespace=None,
                        name="coherence",
                        version="0.5.2",
                        qualifiers={},
                        subpath=None,
                    ),
                ),
                AffectedPackage(
                    vulnerable_package=PackageURL(
                        type="hex",
                        namespace=None,
                        name="coherence",
                        version="0.1.3",
                        qualifiers={},
                        subpath=None,
                    ),
                    patched_package=PackageURL(
                        type="hex",
                        namespace=None,
                        name="coherence",
                        version="0.5.2",
                        qualifiers={},
                        subpath=None,
                    ),
                ),
                AffectedPackage(
                    vulnerable_package=PackageURL(
                        type="hex",
                        namespace=None,
                        name="coherence",
                        version="0.2.0",
                        qualifiers={},
                        subpath=None,
                    ),
                    patched_package=PackageURL(
                        type="hex",
                        namespace=None,
                        name="coherence",
                        version="0.5.2",
                        qualifiers={},
                        subpath=None,
                    ),
                ),
                AffectedPackage(
                    vulnerable_package=PackageURL(
                        type="hex",
                        namespace=None,
                        name="coherence",
                        version="0.3.0",
                        qualifiers={},
                        subpath=None,
                    ),
                    patched_package=PackageURL(
                        type="hex",
                        namespace=None,
                        name="coherence",
                        version="0.5.2",
                        qualifiers={},
                        subpath=None,
                    ),
                ),
                AffectedPackage(
                    vulnerable_package=PackageURL(
                        type="hex",
                        namespace=None,
                        name="coherence",
                        version="0.3.1",
                        qualifiers={},
                        subpath=None,
                    ),
                    patched_package=PackageURL(
                        type="hex",
                        namespace=None,
                        name="coherence",
                        version="0.5.2",
                        qualifiers={},
                        subpath=None,
                    ),
                ),
                AffectedPackage(
                    vulnerable_package=PackageURL(
                        type="hex",
                        namespace=None,
                        name="coherence",
                        version="0.4.0",
                        qualifiers={},
                        subpath=None,
                    ),
                    patched_package=PackageURL(
                        type="hex",
                        namespace=None,
                        name="coherence",
                        version="0.5.2",
                        qualifiers={},
                        subpath=None,
                    ),
                ),
                AffectedPackage(
                    vulnerable_package=PackageURL(
                        type="hex",
                        namespace=None,
                        name="coherence",
                        version="0.5.0",
                        qualifiers={},
                        subpath=None,
                    ),
                    patched_package=PackageURL(
                        type="hex",
                        namespace=None,
                        name="coherence",
                        version="0.5.2",
                        qualifiers={},
                        subpath=None,
                    ),
                ),
                AffectedPackage(
                    vulnerable_package=PackageURL(
                        type="hex",
                        namespace=None,
                        name="coherence",
                        version="0.5.1",
                        qualifiers={},
                        subpath=None,
                    ),
                    patched_package=PackageURL(
                        type="hex",
                        namespace=None,
                        name="coherence",
                        version="0.5.2",
                        qualifiers={},
                        subpath=None,
                    ),
                ),
            ],
            references=[
                Reference(
                    reference_id="2aae6e3a-24a3-4d5f-86ff-b964eaf7c6d1",
                ),
                Reference(url="https://github.com/smpallen99/coherence/issues/270"),
            ],
            vulnerability_id="CVE-2018-20301",
        )

        found_advisory = self.data_src.process_file(path)

        assert expected_advisory.normalized() == found_advisory.normalized()
