import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime

from vulnerabilities.importer import AdvisoryData, AffectedPackage, Reference, VulnerabilitySeverity
from vulnerabilities.utils import get_item
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import RANGE_CLASS_BY_SCHEMES
from univers.versions import SemverVersion
from vulnerabilities.pipelines.v2_importers.github_importer import GitHubAPIImporterPipeline
from vulnerabilities.pipelines.v2_importers.github_importer import get_cwes_from_github_advisory, get_purl

@pytest.fixture
def mock_fetch():
    with patch("vulnerabilities.pipelines.v2_importers.github_importer.utils.fetch_github_graphql_query") as mock:
        yield mock


def test_advisories_count(mock_fetch):
    # Mock the GraphQL query response for advisory count
    mock_fetch.return_value = {
        "data": {
            "securityVulnerabilities": {
                "totalCount": 10
            }
        }
    }
    
    pipeline = GitHubAPIImporterPipeline()
    
    count = pipeline.advisories_count()
    
    # Assert that the count is correct
    assert count == 10


def test_collect_advisories(mock_fetch):
    # Mock advisory data for GitHub
    advisory_data = {
        "data": {
            "securityVulnerabilities": {
                "edges": [
                    {
                        "node": {
                            "advisory": {
                                "identifiers": [
                                    {"type": "GHSA", "value": "GHSA-1234-ABCD"}
                                ],
                                "summary": "Sample advisory description",
                                "references": [{"url": "https://github.com/advisories/GHSA-1234-ABCD"}],
                                "severity": "HIGH",
                                "cwes": {
                                    "nodes": [{"cweId": "CWE-123"}]
                                },
                                "publishedAt": "2023-01-01T00:00:00Z"
                            },
                            "firstPatchedVersion": {"identifier": "1.2.3"},
                            "package": {"name": "example-package"},
                            "vulnerableVersionRange": ">=1.0.0,<=1.2.0"
                        }
                    }
                ],
                "pageInfo": {
                    "hasNextPage": False,
                    "endCursor": None
                }
            }
        }
    }

    # Mock the response from GitHub GraphQL query
    mock_fetch.return_value = advisory_data
    
    # Instantiate the pipeline
    pipeline = GitHubAPIImporterPipeline()
    
    # Collect advisories
    advisories = list(pipeline.collect_advisories())
    
    # Check if advisories were correctly parsed
    assert len(advisories) == 1
    advisory = advisories[0]
    
    # Validate advisory fields
    assert advisory.advisory_id == "GHSA-1234-ABCD"
    assert advisory.summary == "Sample advisory description"
    assert advisory.url == "https://github.com/advisories/GHSA-1234-ABCD"
    assert len(advisory.references_v2) == 1
    assert advisory.references_v2[0].reference_id == "GHSA-1234-ABCD"
    assert advisory.severities[0].value == "HIGH"
    
    # Validate affected package and version range
    affected_package = advisory.affected_packages[0]
    assert isinstance(affected_package.package, PackageURL)
    assert affected_package.package.name == "example-package"
    
    # Check CWE extraction
    assert advisory.weaknesses == [123]


def test_get_purl(mock_fetch):
    # Test for package URL generation
    result = get_purl("cargo", "example/package-name")
    
    # Validate that the correct PackageURL is generated
    assert isinstance(result, PackageURL)
    assert result.type == "cargo"
    assert result.namespace == None
    assert result.name == "example/package-name"
    

def test_process_response(mock_fetch):
    # Mock advisory data as input for the process_response function
    advisory_data = {
        "data": {
            "securityVulnerabilities": {
                "edges": [
                    {
                        "node": {
                            "advisory": {
                                "identifiers": [
                                    {"type": "GHSA", "value": "GHSA-5678-EFGH"}
                                ],
                                "summary": "Another advisory",
                                "references": [{"url": "https://github.com/advisories/GHSA-5678-EFGH"}],
                                "severity": "MEDIUM",
                                "cwes": {
                                    "nodes": [{"cweId": "CWE-200"}]
                                },
                                "publishedAt": "2023-02-01T00:00:00Z"
                            },
                            "firstPatchedVersion": {"identifier": "2.0.0"},
                            "package": {"name": "another-package"},
                            "vulnerableVersionRange": ">=2.0.0,<=3.0.0"
                        }
                    }
                ],
                "pageInfo": {
                    "hasNextPage": False,
                    "endCursor": None
                }
            }
        }
    }
    
    # Mock the response from GitHub GraphQL query
    mock_fetch.return_value = advisory_data
    
    # Process the mock response
    result = list(GitHubAPIImporterPipeline().collect_advisories())
    
    # Check the results
    assert len(result) == 1
    advisory = result[0]
    
    # Validate the advisory data
    assert advisory.advisory_id == "GHSA-5678-EFGH"
    assert advisory.summary == "Another advisory"
    assert advisory.url == "https://github.com/advisories/GHSA-5678-EFGH"
    
    # Check CWE extraction
    assert advisory.weaknesses == [200]


def test_get_cwes_from_github_advisory(mock_fetch):
    # Mock CWEs extraction from GitHub advisory
    advisory_data = {
        "cwes": {
            "nodes": [{"cweId": "CWE-522"}]
        }
    }

    cwes = get_cwes_from_github_advisory(advisory_data)
    
    # Validate the CWE ID extraction
    assert cwes == [522]


def test_invalid_package_type_in_get_purl(mock_fetch):
    # Test for invalid package type
    result = get_purl("invalidpkg", "example/package-name")
    
    # Assert that None is returned for an invalid package type
    assert result is None
