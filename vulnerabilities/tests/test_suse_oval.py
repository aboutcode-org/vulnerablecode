#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


import gzip
import io
import os
import xml.etree.ElementTree as ET

from vulnerabilities.importers.suse_oval import SuseOvalImporter
from vulnerabilities.importers.suse_oval import filter
from vulnerabilities.oval_parser import OvalParser
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/suse_oval")


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


def test_suse_oval_parse_leap_micro_5_3():
    xml_doc = ET.parse(os.path.join(TEST_DATA, "opensuse.leap.micro.5.3.xml"))
    translations = {"less than": "<", "equals": "=", "greater than or equal": ">="}
    parsed_oval = OvalParser(translations, xml_doc)

    # Get total number of definitions
    assert len(parsed_oval.all_definitions) == 104

    # Get definition `id`: the `<definition>` element.
    definition_1 = parsed_oval.all_definitions[0]
    assert parsed_oval.all_definitions[0].getId() == "oval:org.opensuse.security:def:201918348"
    assert parsed_oval.all_definitions[1].getId() == "oval:org.opensuse.security:def:20192708"

    # Get definition `test_ref`: the `<criterion>` element.
    definition_1_test_ids = {
        "oval:org.opensuse.security:tst:2009726610",
        "oval:org.opensuse.security:tst:2009726611",
        "oval:org.opensuse.security:tst:2009726612",
    }
    assert definition_1_test_ids == {
        i.getId() for i in parsed_oval.get_tests_of_definition(definition_1)
    }

    # Get vuln_id from definition
    vuln_id_1 = ["CVE-2019-18348"]
    assert vuln_id_1 == parsed_oval.get_vuln_id_from_definition(definition_1)

    # Get total number of tests
    assert len(parsed_oval.oval_document.getTests()) == 3110

    # Get test object and test state
    test_1 = parsed_oval.oval_document.getTests()[0]
    obj_t1, state_t1 = parsed_oval.get_object_state_of_test(test_1)
    assert obj_t1.getId() == "oval:org.opensuse.security:obj:2009030416"
    assert state_t1.getId() == "oval:org.opensuse.security:ste:2009169740"

    # Get total number of packages: `rpminfo_object` elements
    assert len(parsed_oval.oval_document.getObjects()) == 336

    # Get packages
    obj_t1 = parsed_oval.oval_document.getObjects()[0]
    obj_t2 = parsed_oval.oval_document.getObjects()[1]

    pkg_set1 = set(parsed_oval.get_pkgs_from_obj(obj_t1))
    pkg_set2 = set(parsed_oval.get_pkgs_from_obj(obj_t2))

    assert pkg_set1 == {"kernel-default"}
    assert pkg_set2 == {"kgraft-patch-3_12_38-44-default"}

    # Get total number of versions: `rpminfo_state` elements
    assert len(parsed_oval.oval_document.getStates()) == 764

    # Get versions
    state_1 = parsed_oval.oval_document.getStates()[0]
    state_2 = parsed_oval.oval_document.getStates()[1]

    exp_range_1 = "=3.12.38-44.1"
    exp_range_2 = ">=5-2.1-0"

    assert parsed_oval.get_version_range_from_state(state_1) == exp_range_1
    assert parsed_oval.get_version_range_from_state(state_2) == exp_range_2

    # Get reference URLs: `ref_url` attribute from `reference` elements
    # We use the 2nd definition because the 1st has a lengthy list of references.
    definition_2 = parsed_oval.all_definitions[1]
    def2_urls = {
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2708",
        "https://www.suse.com/security/cve/CVE-2019-2708",
        "https://lists.suse.com/pipermail/sle-security-updates/2022-November/013108.html",
        "https://lists.suse.com/pipermail/sle-security-updates/2022-November/013106.html",
        "https://lists.suse.com/pipermail/sle-security-updates/2022-November/013158.html",
        "https://www.suse.com/security/cve/CVE-2019-2708/",
        "https://bugzilla.suse.com/1174414",
    }

    assert def2_urls == parsed_oval.get_urls_from_definition(definition_2)


def test_filter_suse_gz_files():
    initial_suse_gz_files = [
        "https://ftp.suse.com/pub/projects/security/oval/suse.openstack.cloud.7-affected.xml.gz",
        "https://ftp.suse.com/pub/projects/security/oval/suse.openstack.cloud.7-patch.xml.gz",
        "https://ftp.suse.com/pub/projects/security/oval/suse.openstack.cloud.7.xml.gz",
        "https://ftp.suse.com/pub/projects/security/oval/suse.openstack.cloud.8-affected.xml.gz",
        "https://ftp.suse.com/pub/projects/security/oval/suse.openstack.cloud.8-patch.xml.gz",
        "https://ftp.suse.com/pub/projects/security/oval/suse.openstack.cloud.8.xml.gz",
        "https://ftp.suse.com/pub/projects/security/oval/suse.openstack.cloud.9-affected.xml.gz",
        "https://ftp.suse.com/pub/projects/security/oval/suse.openstack.cloud.9-patch.xml.gz",
        "https://ftp.suse.com/pub/projects/security/oval/suse.openstack.cloud.9.xml.gz",
        "https://ftp.suse.com/pub/projects/security/oval/suse.storage.6-affected.xml.gz",
        "https://ftp.suse.com/pub/projects/security/oval/suse.storage.6-patch.xml.gz",
        "https://ftp.suse.com/pub/projects/security/oval/suse.storage.6.xml.gz",
        "https://ftp.suse.com/pub/projects/security/oval/suse.storage.7-affected.xml.gz",
        "https://ftp.suse.com/pub/projects/security/oval/suse.storage.7-patch.xml.gz",
        "https://ftp.suse.com/pub/projects/security/oval/suse.storage.7.xml.gz",
    ]

    filtered_initial_suse_gz_files = [
        "https://ftp.suse.com/pub/projects/security/oval/suse.openstack.cloud.7-affected.xml.gz",
        "https://ftp.suse.com/pub/projects/security/oval/suse.openstack.cloud.7-patch.xml.gz",
        "https://ftp.suse.com/pub/projects/security/oval/suse.openstack.cloud.8-affected.xml.gz",
        "https://ftp.suse.com/pub/projects/security/oval/suse.openstack.cloud.8-patch.xml.gz",
        "https://ftp.suse.com/pub/projects/security/oval/suse.openstack.cloud.9-affected.xml.gz",
        "https://ftp.suse.com/pub/projects/security/oval/suse.openstack.cloud.9-patch.xml.gz",
        "https://ftp.suse.com/pub/projects/security/oval/suse.storage.6-affected.xml.gz",
        "https://ftp.suse.com/pub/projects/security/oval/suse.storage.6-patch.xml.gz",
        "https://ftp.suse.com/pub/projects/security/oval/suse.storage.7-affected.xml.gz",
        "https://ftp.suse.com/pub/projects/security/oval/suse.storage.7-patch.xml.gz",
    ]

    assert filter(initial_suse_gz_files) == filtered_initial_suse_gz_files


def test_cve_prefix_filter():
    xml_doc = ET.parse(os.path.join(TEST_DATA, "mock-definitions-only.xml"))
    translations = {"less than": "<", "equals": "=", "greater than or equal": ">="}
    parsed_oval = OvalParser(translations, xml_doc)

    assert len(parsed_oval.all_definitions) == 3

    definition_1 = parsed_oval.all_definitions[0]

    vuln_id_1 = ["CVE-2008-5679"]
    assert vuln_id_1 == parsed_oval.get_vuln_id_from_definition(definition_1)

    definition_2 = parsed_oval.all_definitions[1]

    vuln_id_2 = ["CVE-1234-5678"]
    assert vuln_id_2 == parsed_oval.get_vuln_id_from_definition(definition_2)

    definition_3 = parsed_oval.all_definitions[2]

    vuln_id_3 = ["CVE-1111-2222"]
    assert vuln_id_3 == parsed_oval.get_vuln_id_from_definition(definition_3)
