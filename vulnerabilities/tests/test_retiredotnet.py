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

import os
from unittest import TestCase
from collections import OrderedDict

from packageurl import PackageURL

from vulnerabilities.importers.retiredotnet import RetireDotnetDataSource
from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import Reference
from vulnerabilities.helpers import AffectedPackageWithPatchedPackage

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class TestRetireDotnetDataSource(TestCase):
    @classmethod
    def setUpClass(cls):
        data_source_cfg = {
            "repository_url": "https://test.net",
        }
        cls.data_src = RetireDotnetDataSource(1, config=data_source_cfg)

    def test_vuln_id_from_desc(self):

        gibberish = "xyzabcpqr123" * 50 + "\n" * 100
        res = self.data_src.vuln_id_from_desc(gibberish)
        assert res is None

        desc = "abcdef CVE-2002-1968 pqrstuvwxyz:_|-|"
        res = self.data_src.vuln_id_from_desc(desc)
        assert res == "CVE-2002-1968"

    def test_process_file(self):

        path = os.path.join(BASE_DIR, "test_data/retiredotnet/test_file.json")
        expected_data = Advisory(
            summary="Microsoft Security Advisory CVE-2019-0982: ASP.NET Core Denial of Service Vulnerability",
            vulnerability_id="CVE-2019-0982",
            affected_packages_with_patched_package=[
                AffectedPackageWithPatchedPackage(
                    vulnerable_package=PackageURL(
                        type="nuget",
                        namespace=None,
                        name="Microsoft.AspNetCore.SignalR.Protocols.MessagePack",
                        version="1.0.0",
                    ),
                    patched_package=PackageURL(
                        type="nuget",
                        namespace=None,
                        name="Microsoft.AspNetCore.SignalR.Protocols.MessagePack",
                        version="1.0.11",
                    ),
                ),
                AffectedPackageWithPatchedPackage(
                    vulnerable_package=PackageURL(
                        type="nuget",
                        namespace=None,
                        name="Microsoft.AspNetCore.SignalR.Protocols.MessagePack",
                        version="1.0.1",
                    ),
                    patched_package=PackageURL(
                        type="nuget",
                        namespace=None,
                        name="Microsoft.AspNetCore.SignalR.Protocols.MessagePack",
                        version="1.0.11",
                    ),
                ),
                AffectedPackageWithPatchedPackage(
                    vulnerable_package=PackageURL(
                        type="nuget",
                        namespace=None,
                        name="Microsoft.AspNetCore.SignalR.Protocols.MessagePack",
                        version="1.0.2",
                    ),
                    patched_package=PackageURL(
                        type="nuget",
                        namespace=None,
                        name="Microsoft.AspNetCore.SignalR.Protocols.MessagePack",
                        version="1.0.11",
                    ),
                ),
                AffectedPackageWithPatchedPackage(
                    vulnerable_package=PackageURL(
                        type="nuget",
                        namespace=None,
                        name="Microsoft.AspNetCore.SignalR.Protocols.MessagePack",
                        version="1.0.3",
                    ),
                    patched_package=PackageURL(
                        type="nuget",
                        namespace=None,
                        name="Microsoft.AspNetCore.SignalR.Protocols.MessagePack",
                        version="1.0.11",
                    ),
                ),
                AffectedPackageWithPatchedPackage(
                    vulnerable_package=PackageURL(
                        type="nuget",
                        namespace=None,
                        name="Microsoft.AspNetCore.SignalR.Protocols.MessagePack",
                        version="1.0.4",
                    ),
                    patched_package=PackageURL(
                        type="nuget",
                        namespace=None,
                        name="Microsoft.AspNetCore.SignalR.Protocols.MessagePack",
                        version="1.0.11",
                    ),
                ),
                AffectedPackageWithPatchedPackage(
                    vulnerable_package=PackageURL(
                        type="nuget",
                        namespace=None,
                        name="Microsoft.AspNetCore.SignalR.Protocols.MessagePack",
                        version="1.1.0",
                    ),
                    patched_package=PackageURL(
                        type="nuget",
                        namespace=None,
                        name="Microsoft.AspNetCore.SignalR.Protocols.MessagePack",
                        version="1.1.5",
                    ),
                ),
            ],
            references=[
                Reference(
                    reference_id="",
                    url="https://github.com/aspnet/Announcements/issues/359",
                    severities=[],
                )
            ],
        )

        found_data = self.data_src.process_file(path)

        assert expected_data == found_data
