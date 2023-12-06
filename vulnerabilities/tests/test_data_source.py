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
from unittest.mock import MagicMock
from unittest.mock import patch

from fetchcode.vcs import VCSResponse
from packageurl import PackageURL

from vulnerabilities.importer import Importer
from vulnerabilities.importer import OvalImporter
from vulnerabilities.importers.elixir_security import ElixirSecurityImporter
from vulnerabilities.importers.fireeye import FireyeImporter
from vulnerabilities.importers.gentoo import GentooImporter
from vulnerabilities.importers.gitlab import GitLabAPIImporter
from vulnerabilities.importers.istio import IstioImporter
from vulnerabilities.importers.mozilla import MozillaImporter
from vulnerabilities.importers.npm import NpmImporter
from vulnerabilities.importers.pypa import PyPaImporter
from vulnerabilities.importers.retiredotnet import RetireDotnetImporter
from vulnerabilities.oval_parser import OvalParser

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/")


def load_oval_data():
    etrees_of_oval = {}
    for f in os.listdir(TEST_DATA):
        if f.endswith("oval_data.xml"):
            path = os.path.join(TEST_DATA, f)
            provider = f.split("_")[0]
            etrees_of_oval[provider] = ET.parse(path)
    return etrees_of_oval


class MockOvalImporter(OvalImporter):
    spdx_license_expression = "FOO-BAR"


class MockGitImporter(Importer):
    spdx_license_expression = "FOO-BAR"


def test_create_purl():
    purl1 = PackageURL(name="ffmpeg", type="test")

    assert purl1 == MockOvalImporter().create_purl(pkg_name="ffmpeg", pkg_data={"type": "test"})

    purl2 = PackageURL(
        name="notepad",
        type="example",
        namespace="ns",
        qualifiers={"distro": "sample"},
        subpath="root",
    )
    assert purl2 == MockOvalImporter().create_purl(
        pkg_name="notepad",
        pkg_data={
            "namespace": "ns",
            "qualifiers": {"distro": "sample"},
            "subpath": "root",
            "type": "example",
        },
    )


def test__collect_pkgs():

    xmls = load_oval_data()

    expected_suse_pkgs = {"cacti-spine", "apache2-mod_perl", "cacti", "apache2-mod_perl-devel"}
    expected_ubuntu_pkgs = {"potrace", "tor"}

    translations = {"less than": "<"}

    found_suse_pkgs = MockOvalImporter()._collect_pkgs(
        OvalParser(translations, xmls["suse"]).get_data()
    )

    found_ubuntu_pkgs = MockOvalImporter()._collect_pkgs(
        OvalParser(translations, xmls["ubuntu"]).get_data()
    )

    assert found_suse_pkgs == expected_suse_pkgs
    assert found_ubuntu_pkgs == expected_ubuntu_pkgs


@patch("vulnerabilities.importer.fetch_via_vcs")
def test_git_importer(mock_clone):
    mock_clone.return_value = VCSResponse(
        dest_dir="test",
        vcs_type="git",
        domain="test",
    )
    git_importer = MockGitImporter()
    git_importer.clone("test-url") == VCSResponse(
        dest_dir="test",
        vcs_type="git",
        domain="test",
    )


def test_git_importer_clone():
    git_importers = [
        ElixirSecurityImporter,
        FireyeImporter,
        GentooImporter,
        GitLabAPIImporter,
        IstioImporter,
        MozillaImporter,
        NpmImporter,
        RetireDotnetImporter,
        PyPaImporter,
    ]
    for git_importer in git_importers:
        mock_function = MagicMock(
            return_value=VCSResponse(
                dest_dir="test",
                vcs_type="git",
                domain="test",
            )
        )
        with patch("vulnerabilities.importer.fetch_via_vcs", mock_function) as mock_fetch:
            with patch.object(VCSResponse, "delete") as mock_delete:
                list(git_importer().advisory_data())
                mock_fetch.assert_called_once()
                mock_delete.assert_called_once()
