from unittest.mock import patch
from vulnerabilities.importers.csaf import CSAFImporter


@patch("vulnerabilities.importers.csaf.requests.get")
def test_csaf_importer_fetch_and_parse(mock_get):
    # Mock response for individual CSAF file parsing
    sample_csaf = {
        "document": {
            "title": "DHIS2 SQL Injection",
            "references": [{"url": "https://example.com/ref"}]
        },
        "vulnerabilities": [
            {
                "cve": "CVE-2026-99999",
                "notes": [{"category": "summary", "text": "SQL Injection vulnerability"}]
            }
        ]
    }

    importer = CSAFImporter()
    advisories = list(importer.parse(sample_csaf))

    assert len(advisories) == 1
    assert advisories[0].aliases == ["CVE-2026-99999"]
    assert advisories[0].summary == "SQL Injection vulnerability"