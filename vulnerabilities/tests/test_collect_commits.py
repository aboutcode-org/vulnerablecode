from unittest.mock import patch

from vulnerabilities.models import CodeFix
from vulnerabilities.pipelines.collect_commits import CollectFixCommitsPipeline
from vulnerabilities.pipelines.collect_commits import is_reference_already_processed
from vulnerabilities.pipelines.collect_commits import normalize_vcs_url


# --- Mocked Dependencies ---
class MockVulnerability:
    def __init__(self, id):
        self.id = id


class MockReference:
    def __init__(self, url, vulnerabilities):
        self.url = url
        self.vulnerabilities = vulnerabilities


class MockPackage:
    def __init__(self, purl):
        self.purl = purl


# --- Tests for Utility Functions ---
@patch("vulnerabilities.models.CodeFix.objects.filter")
def test_reference_already_processed_true(mock_filter):
    mock_filter.return_value.exists.return_value = True
    result = is_reference_already_processed("http://example.com", "commit123")
    assert result is True
    mock_filter.assert_called_once_with(
        references__contains=["http://example.com"], commits__contains=["commit123"]
    )


@patch("vulnerabilities.models.CodeFix.objects.filter")
def test_reference_already_processed_false(mock_filter):
    mock_filter.return_value.exists.return_value = False
    result = is_reference_already_processed("http://example.com", "commit123")
    assert result is False


# --- Tests for normalize_vcs_url ---
def test_normalize_plain_url():
    url = normalize_vcs_url("https://github.com/user/repo.git")
    assert url == "https://github.com/user/repo.git"


def test_normalize_git_ssh_url():
    url = normalize_vcs_url("git@github.com:user/repo.git")
    assert url == "https://github.com/user/repo.git"


def test_normalize_implicit_github():
    url = normalize_vcs_url("user/repo")
    assert url == "https://github.com/user/repo"


# --- Tests for CollectFixCommitsPipeline ---
@patch("vulnerabilities.models.VulnerabilityReference.objects.prefetch_related")
@patch("vulnerabilities.pipelines.collect_commits.CollectFixCommitsPipeline.get_or_create_package")
@patch("vulnerabilities.pipelines.collect_commits.is_reference_already_processed")
@patch("vulnerabilities.pipelines.collect_commits.url2purl")
def test_collect_and_store_fix_commits(
    mock_url2purl, mock_is_processed, mock_get_package, mock_prefetch
):
    mock_vuln = MockVulnerability(id=1)
    mock_reference = MockReference(url="http://example.com", vulnerabilities=[mock_vuln])
    mock_prefetch.return_value.distinct.return_value.paginated.return_value = [mock_reference]
    mock_url2purl.return_value = "pkg:example/package@1.0.0"
    mock_is_processed.return_value = False
    mock_get_package.return_value = MockPackage(purl="pkg:example/package@1.0.0")

    pipeline = CollectFixCommitsPipeline()
    pipeline.log = lambda msg: None
    pipeline.collect_and_store_fix_commits()

    mock_is_processed.assert_called_once_with("http://example.com", "pkg:example/package@1.0.0")
    mock_get_package.assert_called_once_with("pkg:example/package@1.0.0")


@patch("vulnerabilities.pipelines.collect_commits.CollectFixCommitsPipeline.get_or_create_package")
def test_get_or_create_package_success(mock_get_or_create):
    mock_get_or_create.return_value = (MockPackage(purl="pkg:example/package@1.0.0"), True)
    pipeline = CollectFixCommitsPipeline()
    package = pipeline.get_or_create_package("pkg:example/package@1.0.0")
    assert package.purl == "pkg:example/package@1.0.0"


@patch("vulnerabilities.pipelines.collect_commits.CollectFixCommitsPipeline.get_or_create_package")
def test_get_or_create_package_failure(mock_get_or_create):
    mock_get_or_create.side_effect = Exception("Error")
    pipeline = CollectFixCommitsPipeline()
    logs = []
    pipeline.log = lambda msg: logs.append(msg)
    result = pipeline.get_or_create_package("pkg:example/package@1.0.0")
    assert result is None
    assert len(logs) == 1


@patch("vulnerabilities.models.CodeFix.objects.get_or_create")
def test_create_codefix_entry_success(mock_get_or_create):
    mock_get_or_create.return_value = (CodeFix(), True)
    pipeline = CollectFixCommitsPipeline()
    result = pipeline.create_codefix_entry(
        MockVulnerability(1),
        MockPackage("pkg:example/package@1.0.0"),
        "http://example.com",
        "http://reference",
    )
    assert result is not None
    mock_get_or_create.assert_called_once()


@patch("vulnerabilities.models.CodeFix.objects.get_or_create")
def test_create_codefix_entry_failure(mock_get_or_create):
    mock_get_or_create.side_effect = Exception("Error")
    pipeline = CollectFixCommitsPipeline()
    logs = []
    pipeline.log = lambda msg: logs.append(msg)
    result = pipeline.create_codefix_entry(
        MockVulnerability(1),
        MockPackage("pkg:example/package@1.0.0"),
        "http://example.com",
        "http://reference",
    )
    assert result is None
    assert len(logs) == 1
