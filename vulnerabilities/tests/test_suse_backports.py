#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

# from collections import OrderedDict
# import os
# from unittest import TestCase
# import yaml

# from packageurl import PackageURL

# from vulnerabilities.importers.suse_backports import SUSEBackportsImporter
# from vulnerabilities.importer import AdvisoryData

# BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# def yaml_loader():
#     path = os.path.join(BASE_DIR, "test_data/suse_backports/")
#     yaml_files = {}
#     for file in os.listdir(path):
#         with open(os.path.join(path, file)) as f:
#             yaml_files[file] = yaml.safe_load(f)
#     return yaml_files


# class TestSUSEBackportsImporter(TestCase):
#     @classmethod
#     def setUpClass(cls):
#         data_source_cfg = {"url": "https://endpoint.com", "etags": {}}
#         cls.data_src = SUSEBackportsImporter(1, config=data_source_cfg)

#     def test_process_file(self):
#         parsed_yamls = yaml_loader()
#         expected_data = [
#             Advisory(
#                 summary="",
#                 impacted_package_urls=[],
#                 resolved_package_urls=[
#                     PackageURL(
#                         type="rpm",
#                         namespace="opensuse",
#                         name="MozillaFirefox",
#                         version="3.0.10-1.1.1",
#                         qualifiers=OrderedDict(),
#                         subpath=None,
#                     )
#                 ],
#                 vulnerability_id="CVE-2009-1313",
#             ),
#             Advisory(
#                 summary="",
#                 impacted_package_urls=[],
#                 resolved_package_urls=[
#                     PackageURL(
#                         type="rpm",
#                         namespace="opensuse",
#                         name="MozillaFirefox-branding-SLED",
#                         version="3.5-1.1.5",
#                         qualifiers=OrderedDict(),
#                         subpath=None,
#                     )
#                 ],
#                 vulnerability_id="CVE-2009-1313",
#             ),
#             Advisory(
#                 summary="",
#                 impacted_package_urls=[],
#                 resolved_package_urls=[
#                     PackageURL(
#                         type="rpm",
#                         namespace="opensuse",
#                         name="MozillaFirefox-translations",
#                         version="3.0.10-1.1.1",
#                         qualifiers=OrderedDict(),
#                         subpath=None,
#                     )
#                 ],
#                 vulnerability_id="CVE-2009-1313",
#             ),
#             Advisory(
#                 summary="",
#                 impacted_package_urls=[],
#                 resolved_package_urls=[
#                     PackageURL(
#                         type="rpm",
#                         namespace="opensuse",
#                         name="NetworkManager",
#                         version="0.7.0.r4359-15.9.2",
#                         qualifiers=OrderedDict(),
#                         subpath=None,
#                     )
#                 ],
#                 vulnerability_id="CVE-2009-0365",
#             ),
#             Advisory(
#                 summary="",
#                 impacted_package_urls=[],
#                 resolved_package_urls=[
#                     PackageURL(
#                         type="rpm",
#                         namespace="opensuse",
#                         name="NetworkManager",
#                         version="0.7.0.r4359-15.9.2",
#                         qualifiers=OrderedDict(),
#                         subpath=None,
#                     )
#                 ],
#                 vulnerability_id="CVE-2009-0578",
#             ),
#         ]

#         found_data = self.data_src.process_file(parsed_yamls["backports-sle11-sp0.yaml"])

#         found_advisories = list(map(Advisory.normalized, found_data))
#         expected_advisories = list(map(Advisory.normalized, expected_data))
#         assert sorted(found_advisories) == sorted(expected_advisories)
