#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


import os
from collections import OrderedDict
from unittest import TestCase

from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Reference
from vulnerabilities.importers.retiredotnet import RetireDotnetImporter
from vulnerabilities.utils import AffectedPackage

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class TestRetireDotnetImporter(TestCase):
    @classmethod
    def setUpClass(cls):
        data_source_cfg = {
            "repository_url": "https://test.net",
        }
        cls.data_src = RetireDotnetImporter(1, config=data_source_cfg)

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
            affected_packages=[
                AffectedPackage(
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
                AffectedPackage(
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
                AffectedPackage(
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
                AffectedPackage(
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
                AffectedPackage(
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
                AffectedPackage(
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
