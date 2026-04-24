from unittest import mock

from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import EbuildVersionRange
from univers.versions import GentooVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.improver import MAX_CONFIDENCE
from vulnerabilities.improvers.gentoo import GentooBasicImprover
from vulnerabilities.improvers.gentoo import fetch_gentoo_package_versions
from vulnerabilities.improvers.gentoo import get_last_revision
from vulnerabilities.improvers.gentoo import get_revision_versions


def test_get_revision_versions():
    all_versions = ["1.2.3", "1.2.3-r1", "1.2.3-r2", "1.2.4", "1.2.4-r1", "1.3.0"]

    result = get_revision_versions("1.2.3", all_versions)
    assert result == ["1.2.3", "1.2.3-r1", "1.2.3-r2"]

    result = get_revision_versions("1.2.4", all_versions)
    assert result == ["1.2.4", "1.2.4-r1"]

    result = get_revision_versions("1.3.0", all_versions)
    assert result == ["1.3.0"]

    result = get_revision_versions("2.0.0", all_versions)
    assert result == []


def test_get_revision_versions_with_revision_input():
    all_versions = ["1.2.3", "1.2.3-r1", "1.2.3-r2"]
    result = get_revision_versions("1.2.3-r1", all_versions)
    assert result == ["1.2.3", "1.2.3-r1", "1.2.3-r2"]


def test_get_last_revision():
    all_versions = ["1.2.3", "1.2.3-r1", "1.2.3-r2", "1.2.4"]

    result = get_last_revision("1.2.3", all_versions)
    assert result == "1.2.3-r2"

    result = get_last_revision("1.2.4", all_versions)
    assert result == "1.2.4"

    result = get_last_revision("9.9.9", all_versions)
    assert result is None


def test_fetch_gentoo_package_versions_success():
    mock_response = mock.Mock()
    mock_response.json.return_value = {
        "versions": [
            {"version": "1.14.5-r3"},
            {"version": "1.14.5-r2"},
            {"version": "1.14.4"},
        ]
    }
    mock_response.raise_for_status = mock.Mock()

    with mock.patch("requests.get", return_value=mock_response) as mock_get:
        result = fetch_gentoo_package_versions("dev-vcs", "subversion")
        assert result == ["1.14.5-r3", "1.14.5-r2", "1.14.4"]
        mock_get.assert_called_once_with(
            "https://packages.gentoo.org/packages/dev-vcs/subversion.json",
            timeout=30,
        )


def test_fetch_gentoo_package_versions_failure():
    with mock.patch("requests.get", side_effect=Exception("Network error")):
        result = fetch_gentoo_package_versions("dev-vcs", "subversion")
        assert result == []


def test_gentoo_improver_get_package_versions():
    improver = GentooBasicImprover()

    purl = PackageURL(type="ebuild", namespace="dev-vcs", name="subversion")
    with mock.patch(
        "vulnerabilities.improvers.gentoo.fetch_gentoo_package_versions",
        return_value=["1.14.5", "1.14.4"],
    ):
        result = improver.get_package_versions(purl)
        assert result == ["1.14.5", "1.14.4"]

    non_ebuild_purl = PackageURL(type="npm", namespace="", name="lodash")
    result = improver.get_package_versions(non_ebuild_purl)
    assert result == []

    no_ns_purl = PackageURL(type="ebuild", name="test")
    result = improver.get_package_versions(no_ns_purl)
    assert result == []


def test_gentoo_improver_get_inferences():
    improver = GentooBasicImprover()

    purl = PackageURL(type="ebuild", namespace="dev-vcs", name="subversion")
    affected_version_range = EbuildVersionRange(
        constraints=[
            VersionConstraint(version=GentooVersion("1.9.7"), comparator="<"),
        ]
    )
    advisory_data = AdvisoryData(
        aliases=["CVE-2017-9800"],
        summary="Test vulnerability",
        affected_packages=[
            AffectedPackage(
                package=purl,
                affected_version_range=affected_version_range,
            ),
        ],
        references=[
            Reference(
                reference_id="GLSA-201709-09",
                url="https://security.gentoo.org/glsa/201709-09",
            )
        ],
        url="https://security.gentoo.org/glsa/201709-09",
    )

    mock_versions = ["1.9.7", "1.9.6", "1.9.5", "1.8.18", "1.8.17"]
    with mock.patch(
        "vulnerabilities.improvers.gentoo.fetch_gentoo_package_versions",
        return_value=mock_versions,
    ):
        inferences = list(improver.get_inferences(advisory_data))
        assert len(inferences) > 0
        for inference in inferences:
            assert inference.confidence == MAX_CONFIDENCE
            assert inference.aliases == ["CVE-2017-9800"]
            for affected_purl in inference.affected_purls:
                assert affected_purl.type == "ebuild"
                assert affected_purl.namespace == "dev-vcs"
                assert affected_purl.name == "subversion"
                assert affected_purl.version in ["1.9.6", "1.9.5", "1.8.18", "1.8.17"]


def test_gentoo_improver_get_inferences_no_affected_packages():
    improver = GentooBasicImprover()
    advisory_data = AdvisoryData(
        aliases=["CVE-2017-9800"],
        summary="Test vulnerability",
        affected_packages=[],
        references=[],
        url="https://security.gentoo.org/glsa/201709-09",
    )
    inferences = list(improver.get_inferences(advisory_data))
    assert inferences == []


def test_gentoo_improver_get_inferences_no_versions_available():
    improver = GentooBasicImprover()

    purl = PackageURL(type="ebuild", namespace="dev-vcs", name="subversion")
    affected_version_range = EbuildVersionRange(
        constraints=[
            VersionConstraint(version=GentooVersion("1.9.7"), comparator="<"),
        ]
    )
    advisory_data = AdvisoryData(
        aliases=["CVE-2017-9800"],
        summary="Test vulnerability",
        affected_packages=[
            AffectedPackage(
                package=purl,
                affected_version_range=affected_version_range,
            ),
        ],
        references=[],
        url="https://security.gentoo.org/glsa/201709-09",
    )

    with mock.patch(
        "vulnerabilities.improvers.gentoo.fetch_gentoo_package_versions",
        return_value=[],
    ):
        inferences = list(improver.get_inferences(advisory_data))
        assert inferences == []
