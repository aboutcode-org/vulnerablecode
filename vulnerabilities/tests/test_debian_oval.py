import os
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch

from packageurl import PackageURL

from vulnerabilities.helpers import AffectedPackage
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importers.debian_oval import DebianOvalImporter
from vulnerabilities.package_managers import VersionResponse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/")


async def mock(a, b):
    pass


def return_adv(_, a):
    return a


class TestDebianOvalImporter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data_source_cfg = {"releases": "eg-debian_oval", "etags": {}}
        cls.debian_oval_data_src = DebianOvalImporter(batch_size=1, config=data_source_cfg)

    @patch(
        "vulnerabilities.importers.debian_oval.DebianVersionAPI.get",
        return_value=VersionResponse(
            valid_versions={"1.11.1+dfsg-5+deb7u1", "0.11.1+dfsg-5+deb7u1", "2.3.9"}
        ),
    )
    @patch("vulnerabilities.importers.debian_oval.DebianVersionAPI.load_api", new=mock)
    def test_get_data_from_xml_doc(self, mock_write):
        expected_advisories = [
            Advisory(
                summary="denial of service",
                vulnerability_id="CVE-2002-2443",
                affected_packages=[
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="deb",
                            namespace=None,
                            name="krb5",
                            version="0.11.1+dfsg-5+deb7u1",
                            qualifiers={"distro": "wheezy"},
                            subpath=None,
                        ),
                        patched_package=PackageURL(
                            type="deb",
                            namespace=None,
                            name="krb5",
                            version="1.11.1+dfsg-5+deb7u1",
                            qualifiers={"distro": "wheezy"},
                            subpath=None,
                        ),
                    )
                ],
                references=[],
            ),
            Advisory(
                summary="security update",
                vulnerability_id="CVE-2001-1593",
                affected_packages=[
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="deb",
                            namespace=None,
                            name="a2ps",
                            version="0.11.1+dfsg-5+deb7u1",
                            qualifiers={"distro": "wheezy"},
                            subpath=None,
                        ),
                        patched_package=None,
                    ),
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="deb",
                            namespace=None,
                            name="a2ps",
                            version="1.11.1+dfsg-5+deb7u1",
                            qualifiers={"distro": "wheezy"},
                            subpath=None,
                        ),
                        patched_package=None,
                    ),
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="deb",
                            namespace=None,
                            name="a2ps",
                            version="2.3.9",
                            qualifiers={"distro": "wheezy"},
                            subpath=None,
                        ),
                        patched_package=None,
                    ),
                ],
                references=[],
            ),
        ]

        xml_doc = ET.parse(os.path.join(TEST_DATA, "debian_oval_data.xml"))
        # Dirty quick patch to mock batch_advisories
        with patch(
            "vulnerabilities.importers.debian_oval.DebianOvalImporter.batch_advisories",
            new=return_adv,
        ):
            found_advisories = [
                i
                for i in self.debian_oval_data_src.get_data_from_xml_doc(
                    xml_doc, {"type": "deb", "qualifiers": {"distro": "wheezy"}}
                )
            ]

        found_advisories = list(map(Advisory.normalized, found_advisories))
        expected_advisories = list(map(Advisory.normalized, expected_advisories))
        assert sorted(found_advisories) == sorted(expected_advisories)
