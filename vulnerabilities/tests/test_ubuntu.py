import os
import unittest
from unittest.mock import patch
from unittest.mock import MagicMock
import xml.etree.ElementTree as ET
from collections import OrderedDict
import asyncio

from dephell_specifier import RangeSpecifier
from packageurl import PackageURL

from vulnerabilities.oval_parser import OvalParser
from vulnerabilities.importers.ubuntu import UbuntuDataSource
from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import Reference

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/")

class TestUbuntuOvalParser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        xml_doc = ET.parse(os.path.join(TEST_DATA, "ubuntu_oval_data.xml"))
        translator = {"less than": "<"}
        cls.parsed_oval = OvalParser(translator, xml_doc)

    def setUp(self):
        self.definition_1 = self.parsed_oval.all_definitions[0]
        self.definition_2 = self.parsed_oval.all_definitions[1]

    def test_get_definitions(self):

        assert len(self.parsed_oval.all_definitions) == 2
        assert (
            self.parsed_oval.all_definitions[0].getId()
            == "oval:com.ubuntu.bionic:def:201687030000000"
        )
        assert (
            self.parsed_oval.all_definitions[1].getId()
            == "oval:com.ubuntu.bionic:def:201688600000000"
        )

    def test_get_tests_of_definition(self):

        definition_1_test_id = {"oval:com.ubuntu.bionic:tst:201686860000000"}
        definition_2_test_id = {"oval:com.ubuntu.bionic:tst:201688600000000"}

        for test in self.parsed_oval.get_tests_of_definition(self.definition_1):
            assert test.getId() in definition_1_test_id

        for test in self.parsed_oval.get_tests_of_definition(self.definition_2):
            assert test.getId() in definition_2_test_id

    def test_get_vuln_id_from_definition(self):

        vuln_id_1 = "CVE-2016-8703"
        vuln_id_2 = "CVE-2016-8860"

        assert vuln_id_1 == self.parsed_oval.get_vuln_id_from_definition(
            self.definition_1
        )
        assert vuln_id_2 == self.parsed_oval.get_vuln_id_from_definition(
            self.definition_2
        )

    def test_get_object_state_of_test(self):

        assert len(self.parsed_oval.oval_document.getTests()) == 2

        test_1 = self.parsed_oval.oval_document.getTests()[0]
        test_2 = self.parsed_oval.oval_document.getTests()[1]

        obj_t1, state_t1 = self.parsed_oval.get_object_state_of_test(test_1)
        obj_t2, state_t2 = self.parsed_oval.get_object_state_of_test(test_2)

        assert state_t2.getId() == "oval:com.ubuntu.bionic:ste:201688600000000"
        assert state_t1.getId() == "oval:com.ubuntu.bionic:ste:201686860000000"

        assert obj_t2.getId() == "oval:com.ubuntu.bionic:obj:2017115650000000"
        assert obj_t1.getId() == "oval:com.ubuntu.bionic:obj:201686860000000"

    def test_get_pkgs_from_obj(self):

        assert len(self.parsed_oval.oval_document.getObjects()) == 2

        obj_t1 = self.parsed_oval.oval_document.getObjects()[0]
        obj_t2 = self.parsed_oval.oval_document.getObjects()[1]

        pkg_set1 = set(self.parsed_oval.get_pkgs_from_obj(obj_t2))
        pkg_set2 = set(self.parsed_oval.get_pkgs_from_obj(obj_t1))

        assert pkg_set1 == {"potrace"}
        assert pkg_set2 == {"tor"}

    def test_get_versionsrngs_from_state(self):

        assert len(self.parsed_oval.oval_document.getStates()) == 2

        state_1 = self.parsed_oval.oval_document.getStates()[0]
        state_2 = self.parsed_oval.oval_document.getStates()[1]

        exp_range_1 = RangeSpecifier("<1.14-2")
        exp_range_2 = RangeSpecifier("<0.2.8.9-1ubuntu1")

        assert self.parsed_oval.get_versionsrngs_from_state(state_1) == exp_range_1
        assert self.parsed_oval.get_versionsrngs_from_state(state_2) == exp_range_2

    def test_get_urls_from_definition(self):

        def1_urls = {'http://people.canonical.com/~ubuntu-security/cve/2016/CVE-2016-8703.html',
                     'https://blogs.gentoo.org/ago/2016/08/08/potrace-multiplesix-heap-based-buffer-overflow-in-bm_readbody_bmp-bitmap_io-c/',
                     'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-8703'
                    }

        assert def1_urls == self.parsed_oval.get_urls_from_definition(self.definition_1)

        def2_urls = {'http://people.canonical.com/~ubuntu-security/cve/2016/CVE-2016-8860.html',
                     'https://trac.torproject.org/projects/tor/ticket/20384',
                     'https://blog.torproject.org/blog/tor-0289-released-important-fixes',
                     'https://github.com/torproject/tor/commit/3cea86eb2fbb65949673eb4ba8ebb695c87a57ce',
                     'http://www.openwall.com/lists/oss-security/2016/10/18/11',
                     'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-8860',
                    }

        assert def2_urls == self.parsed_oval.get_urls_from_definition(self.definition_2)

    def test_get_data(self):

        expected_data = [
            {
                "test_data": [
                    {
                        "package_list": ["potrace"],
                        "version_ranges": RangeSpecifier("<1.14-2"),
                    }
                ],
                "description": "Heap-based buffer overflow in the bm_readbody_bmp function in bitmap_io.c in potrace before 1.13 allows remote attackers to have unspecified impact via a crafted BMP image, a different vulnerability than CVE-2016-8698, CVE-2016-8699, CVE-2016-8700, CVE-2016-8701, and CVE-2016-8702.",
                "vuln_id": "CVE-2016-8703",
                "reference_urls":{
                                  'http://people.canonical.com/~ubuntu-security/cve/2016/CVE-2016-8703.html',
                                  'https://blogs.gentoo.org/ago/2016/08/08/potrace-multiplesix-heap-based-buffer-overflow-in-bm_readbody_bmp-bitmap_io-c/',
                                  'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-8703'
                                }

            },
            {
                "test_data": [
                    {
                        "package_list": ["tor"],
                        "version_ranges": RangeSpecifier("<0.2.8.9-1ubuntu1"),
                    }
                ],
                "description": "Tor before 0.2.8.9 and 0.2.9.x before 0.2.9.4-alpha had internal functions that were entitled to expect that buf_t data had NUL termination, but the implementation of or/buffers.c did not ensure that NUL termination was present, which allows remote attackers to cause a denial of service (client, hidden service, relay, or authority crash) via crafted data.",
                "vuln_id": "CVE-2016-8860",
                "reference_urls":{
                     'http://people.canonical.com/~ubuntu-security/cve/2016/CVE-2016-8860.html',
                     'https://trac.torproject.org/projects/tor/ticket/20384',
                     'https://blog.torproject.org/blog/tor-0289-released-important-fixes',
                     'https://github.com/torproject/tor/commit/3cea86eb2fbb65949673eb4ba8ebb695c87a57ce',
                     'http://www.openwall.com/lists/oss-security/2016/10/18/11',
                     'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-8860',
                    }

            },
        ]

        assert expected_data == self.parsed_oval.get_data()

#This is horrible, there might be a better way
async def mock(a,b):
    pass

def return_adv(_,a):
    return a

class TestUbuntuDataSource(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        data_source_cfg = {
        'releases': 'eg-ubuntu',"etags":{}}
        cls.ubuntu_data_src = UbuntuDataSource(
            batch_size=1, config=data_source_cfg)

    @patch(
        'vulnerabilities.importers.ubuntu.LaunchpadVersionAPI.get',
        return_value={
            '0.3.0',
            '0.2.0',
            '2.14-2'})
    @patch('vulnerabilities.importers.ubuntu.LaunchpadVersionAPI.load_api',new=mock)
    def test_get_data_from_xml_doc(self, mock_write):
        expected_data = {
            Advisory(
                summary=('Tor before 0.2.8.9 and 0.2.9.x before 0.2.9.4-alpha had '
                'internal functions that were entitled to expect that buf_t data had '
                'NUL termination, but the implementation of or/buffers.c did not '
                'ensure that NUL termination was present, which allows remote '
                'attackers to cause a denial of service (client, hidden '
                'service, relay, or authority crash) via crafted data.'),
                impacted_package_urls={
                    PackageURL(
                        type='deb',
                        namespace=None,
                        name='tor',
                        version='0.2.0',
                        qualifiers=OrderedDict(),
                        subpath=None)},
                resolved_package_urls={
                    PackageURL(
                        type='deb',
                        namespace=None,
                        name='tor',
                        version='0.3.0',
                        qualifiers=OrderedDict(),
                        subpath=None),
                    PackageURL(
                        type='deb',
                        namespace=None,
                        name='tor',
                        version='2.14-2',
                        qualifiers=OrderedDict(),
                        subpath=None)},
                vuln_references=sorted([
                    Reference(url='http://www.openwall.com/lists/oss-security/2016/10/18/11'),
                    Reference(url='https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-8860'),
                    Reference(url='http://people.canonical.com/~ubuntu-security/cve/2016/CVE-2016-8860.html'),
                    Reference(url='https://github.com/torproject/tor/commit/3cea86eb2fbb65949673eb4ba8ebb695c87a57ce'),
                    Reference(url='https://blog.torproject.org/blog/tor-0289-released-important-fixes'),
                    Reference(url='https://trac.torproject.org/projects/tor/ticket/20384')],key=lambda x : x.url),
                vulnerability_id='CVE-2016-8860'),
            Advisory(
                summary=('Heap-based buffer overflow in the bm_readbody_bmp function'
                ' in bitmap_io.c in potrace before 1.13 allows remote attackers to '
                'have unspecified impact via a crafted BMP image, a different '
                'vulnerability than CVE-2016-8698, CVE-2016-8699, '
                'CVE-2016-8700, CVE-2016-8701, and CVE-2016-8702.'),
                impacted_package_urls={
                    PackageURL(
                        type='deb',
                        namespace=None,
                        name='potrace',
                        version='0.3.0',
                        qualifiers=OrderedDict(),
                        subpath=None),
                    PackageURL(
                        type='deb',
                        namespace=None,
                        name='potrace',
                        version='0.2.0',
                        qualifiers=OrderedDict(),
                        subpath=None)},
                resolved_package_urls={
                    PackageURL(
                        type='deb',
                        namespace=None,
                        name='potrace',
                        version='2.14-2',
                        qualifiers=OrderedDict(),
                        subpath=None)},
                vuln_references=sorted([
                    Reference(url='http://people.canonical.com/~ubuntu-security/cve/2016/CVE-2016-8703.html'),
                    Reference(url='https://blogs.gentoo.org/ago/2016/08/08/potrace-multiplesix-heap-based-buffer-overflow-in-bm_readbody_bmp-bitmap_io-c/'),
                    Reference(url='https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-8703')],key=lambda x: x.url),
                vulnerability_id='CVE-2016-8703')}

        xml_doc = ET.parse(os.path.join(TEST_DATA, "ubuntu_oval_data.xml"))
        # Dirty quick patch to mock batch_advisories
        with patch('vulnerabilities.importers.ubuntu.UbuntuDataSource.batch_advisories',
         new=return_adv):
            data = {i for i in self.ubuntu_data_src.get_data_from_xml_doc(xml_doc,{"type":"deb"})}
        for adv in data : 
            adv.vuln_references = sorted(adv.vuln_references, key=lambda x : x.url)
        assert expected_data == data