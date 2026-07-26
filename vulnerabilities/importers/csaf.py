import logging
from typing import Iterable

import requests

from vulnerabilities.importer import AdvisoryData, Importer, Reference

logger = logging.getLogger(__name__)


class CSAFImporter(Importer):
    spdx_license_expression = "CC0-1.0"
    notice = "Data provided by CISA CSAF repository."

    # URL to the official CISA IT CSAF ROLIE feed
    FEED_URL = (
        "https://raw.githubusercontent.com/cisagov/CSAF/develop/"
        "csaf_files/IT/white/cisa-csaf-it-feed-tlp-white.json"
    )

    def fetch(self) -> Iterable[dict]:
        """
        Fetches the CISA ROLIE feed and yields individual CSAF advisory JSON payloads.
        """
        response = requests.get(self.FEED_URL)
        if response.status_code != 200:
            logger.error(f"Failed to fetch CSAF feed from {self.FEED_URL}")
            return

        feed_data = response.json()
        entries = feed_data.get("feed", {}).get("entry", [])

        for entry in entries:
            # Extract raw JSON URL for each individual CSAF advisory
            advisory_url = entry.get("content", {}).get("src")
            if not advisory_url:
                continue

            res = requests.get(advisory_url)
            if res.status_code == 200:
                yield res.json()
            else:
                logger.warning(f"Could not download advisory file from {advisory_url}")

    def parse(self, advisory_data: dict) -> Iterable[AdvisoryData]:
        """
        Parses a single CSAF advisory payload into VulnerableCode AdvisoryData objects.
        """
        document = advisory_data.get("document", {})
        title = document.get("title", "")

        # Collect external references
        references = []
        for ref in document.get("references", []):
            url = ref.get("url")
            if url:
                references.append(Reference(url=url))

        # Extract vulnerabilities and associated CVEs
        vulnerabilities = advisory_data.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            cve_id = vuln.get("cve")

            # Extract vulnerability description
            summary = ""
            for note in vuln.get("notes", []):
                if note.get("category") in ("summary", "description", "general"):
                    summary = note.get("text", "")
                    break

            yield AdvisoryData(
                aliases=[cve_id] if cve_id else [],
                summary=summary or title,
                references=references,
            )