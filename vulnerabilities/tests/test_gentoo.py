#
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


import os
import unittest
import xml.etree.ElementTree as ET
from collections import OrderedDict

from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Reference
from vulnerabilities.importers.gentoo import GentooImporter
from vulnerabilities.tests import util_tests
from vulnerabilities.utils import AffectedPackage

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DIR = os.path.join(BASE_DIR, "test_data/gentoo")


def test_gentoo_import():
    file = os.path.join(TEST_DIR, "glsa-201709-09.xml")
    advisories = GentooImporter().process_file(file)
    result = [adv.to_dict() for adv in advisories]
    expected_file = os.path.join(TEST_DIR, "gentoo-expected.json")
    util_tests.check_results_against_json(result, expected_file)


def test_gentoo_import_version_with_slot():
    # See https://github.com/aboutcode-org/vulnerablecode/issues/1921
    # GLSA data can append the SLOT to a version using a colon, e.g.
    # "6.9.3:6", which is not valid Gentoo version syntax on its own.
    file = os.path.join(TEST_DIR, "glsa-202511-03.xml")
    advisories = GentooImporter().process_file(file)
    result = [adv.to_dict() for adv in advisories]
    expected_file = os.path.join(TEST_DIR, "glsa-202511-03-expected.json")
    util_tests.check_results_against_json(result, expected_file)
