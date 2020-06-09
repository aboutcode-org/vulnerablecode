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
from vulnerabilities.importers.debian_oval import DebianOvalDataSource
from vulnerabilities.data_source import Advisory


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/")


async def mock(a, b):
    pass


def return_adv(_, a):
    return a


class TestDebianOvalDataSource(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        data_source_cfg = {
            'releases': 'eg-debian_oval', "etags": {}}
        cls.debian_oval_data_src = DebianOvalDataSource(
            batch_size=1, config=data_source_cfg)

    @patch(
        'vulnerabilities.importers.debian_oval.VersionAPI.get',
        return_value={
            '0:1.11.1+dfsg-5+deb7u1',
            '0:0.11.1+dfsg-5+deb7u1',
            '2.3.9'})
    @patch('vulnerabilities.importers.debian_oval.VersionAPI.load_api', new=mock)
    def test_get_data_from_xml_doc(self, mock_write):
        expected_data = {
            Advisory(
                summary='denial of service',
                impacted_package_urls={
                    PackageURL(
                        type='deb',
                        namespace=None,
                        name='krb5',
                        version='0:0.11.1+dfsg-5+deb7u1',
                        qualifiers=OrderedDict([('distro', 'wheezy')]),
                        subpath=None
                    )},
                resolved_package_urls={
                    PackageURL(
                        type='deb',
                        namespace=None,
                        name='krb5',
                        version='0:1.11.1+dfsg-5+deb7u1',
                        qualifiers=OrderedDict([('distro', 'wheezy')]),
                        subpath=None),
                    PackageURL(
                        type='deb',
                        namespace=None,
                        name='krb5',
                        version='2.3.9',
                        qualifiers=OrderedDict([('distro', 'wheezy')]),
                        subpath=None)},
                reference_urls=set(),
                reference_ids=[],
                cve_id='CVE-2002-2443'
            ),
            Advisory(
                summary='security update',
                impacted_package_urls={
                    PackageURL(
                        type='deb',
                        namespace=None,
                        name='a2ps',
                        version='0:0.11.1+dfsg-5+deb7u1',
                        qualifiers=OrderedDict([('distro', 'wheezy')]),
                        subpath=None
                    )},
                resolved_package_urls={
                    PackageURL(type='deb',
                               namespace=None,
                               name='a2ps',
                               version='2.3.9',
                               qualifiers=OrderedDict([('distro', 'wheezy')]),
                               subpath=None),
                    PackageURL(type='deb',
                               namespace=None,
                               name='a2ps',
                               version='0:1.11.1+dfsg-5+deb7u1',
                               qualifiers=OrderedDict([('distro', 'wheezy')]),
                               subpath=None)},
                reference_urls=set(),
                reference_ids=[],
                cve_id='CVE-2001-1593')

        }

        xml_doc = ET.parse(os.path.join(TEST_DATA, "debian_oval_data.xml"))
        # Dirty quick patch to mock batch_advisories
        with patch('vulnerabilities.importers.debian_oval.DebianOvalDataSource.batch_advisories',
                   new=return_adv):
            data = {i for i in self.debian_oval_data_src.get_data_from_xml_doc(
                xml_doc,
                {
                    "type": "deb",
                    "qualifiers": {"distro": "wheezy"}
                })
            }
        assert expected_data == data
