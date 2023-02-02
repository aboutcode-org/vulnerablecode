#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
import xml.etree.ElementTree as ET

from vulnerabilities.importers.suse_oval import SuseOvalImporter
from vulnerabilities.oval_parser import OvalParser
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/suse_oval")


# TODO: How can we test a .gz file?


# TODO: A question for all these tests and the code more generally: how are the packages
# associated with definitions/aliases/CVEs?
def test_suse_oval_importer_leap_micro_5_3():
    importer = SuseOvalImporter()
    advisories = importer.get_data_from_xml_doc(
        ET.parse(os.path.join(TEST_DATA, "opensuse.leap.micro.5.3.xml")),
        {"type": "rpm", "namespace": "opensuse"},
    )
    expected_file = os.path.join(TEST_DATA, f"suse-oval-leap.micro.5.3-expected.json")
    util_tests.check_results_against_json(
        [advisory.to_dict() for advisory in advisories], expected_file
    )


# TODO: All 80 affected packages (1 for each alias) in the expected JSON are `openSUSE-release`.
# What about the other 54 or so packages identified in the XML file's `object` element?
# See lines 1668-1834.
def test_suse_oval_importer_leap_micro_5_3_patch():
    importer = SuseOvalImporter()
    advisories = importer.get_data_from_xml_doc(
        ET.parse(os.path.join(TEST_DATA, "opensuse.leap.micro.5.3-patch.xml")),
        {"type": "rpm", "namespace": "opensuse"},
    )
    expected_file = os.path.join(TEST_DATA, f"suse-oval-leap.micro.5.3-patch-expected.json")
    util_tests.check_results_against_json(
        [advisory.to_dict() for advisory in advisories], expected_file
    )


# TODO: This creates an 'opera' package in the expected JSON.  Should it also create a
# 'openSUSE-release' package?  See line 64 of the XML file.
def test_suse_oval_importer_CVE_2008_5679():
    importer = SuseOvalImporter()
    advisories = importer.get_data_from_xml_doc(
        ET.parse(os.path.join(TEST_DATA, "org.opensuse.CVE-2008-5679.xml")),
        {"type": "rpm", "namespace": "opensuse"},
    )
    expected_file = os.path.join(TEST_DATA, f"suse-oval-CVE-2008-5679-expected.json")
    util_tests.check_results_against_json(
        [advisory.to_dict() for advisory in advisories], expected_file
    )


# Explore parsing inspired by /vulnerablecode/vulnerabilities/tests/test_suse.py
def test_suse_oval_parse_CVE_2008_5679():
    # xml_doc = ET.parse(os.path.join(TEST_DATA, "org.opensuse.CVE-2008-5679.xml"))
    xml_doc = ET.parse(os.path.join(TEST_DATA, "opensuse.leap.micro.5.3.xml"))
    translations = {"less than": "<", "equals": "=", "greater than or equal": ">="}

    parsed_oval = OvalParser(translations, xml_doc)
    print("\n\ntype(parsed_oval) = {}\n".format(type(parsed_oval)))

    print("parsed_oval.all_definitions = {}".format(parsed_oval.all_definitions))
    print("len(parsed_oval.all_definitions) = {}".format(len(parsed_oval.all_definitions)))

    definition_1 = parsed_oval.all_definitions[0]
    print("\ndefinition_1 = {}".format(definition_1))
    print("definition_1.getId() = {}\n".format(definition_1.getId()))

    # if parsed_oval.all_definitions[1]:
    #     definition_2 = parsed_oval.all_definitions[1]
    #     print("definition_2 = {}".format(definition_2))
    #     print("definition_2.getId() = {}".format(definition_2.getId()))

    # For each definition, we can get tests for that definition
    # i.getId() for i in self.parsed_oval.get_tests_of_definition(self.definition_1)
    test_id_1 = {i.getId() for i in parsed_oval.get_tests_of_definition(definition_1)}
    print("\ntest_id_1 = {}\n".format(test_id_1))

    try:
        definition_2 = parsed_oval.all_definitions[1]
        print("definition_2 = {}".format(definition_2))
        print("definition_2.getId() = {}".format(definition_2.getId()))

        test_id_2 = {i.getId() for i in parsed_oval.get_tests_of_definition(definition_2)}
        print("\ntest_id_2 = {}\n".format(test_id_2))
    except IndexError:
        pass
