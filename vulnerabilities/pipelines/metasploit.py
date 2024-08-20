import logging

import requests
import saneyaml

from vulnerabilities.models import Alias
from vulnerabilities.models import Exploit
from vulnerabilities.pipelines import VulnerableCodePipeline

module_logger = logging.getLogger(__name__)


class MetasploitImproverPipeline(VulnerableCodePipeline):
    """
    Metasploit Exploits Pipeline: Retrieve Metasploit data, iterate through it to identify vulnerabilities
    by their associated aliases, and create or update the corresponding Exploit instances.
    """

    metasploit_data = {}

    @classmethod
    def steps(cls):
        return (
            cls.fetch_exploits,
            cls.add_exploits,
        )

    def fetch_exploits(self):
        url = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
        response = requests.get(url)
        if response.status_code != 200:
            self.log(f"Failed to fetch the Metasploit Exploits: {url}")
            return
        self.metasploit_data = response.json()

    def add_exploits(self):
        for _, record in self.metasploit_data.items():
            vul = None
            for ref in record.get("references", []):
                if ref.startswith("OSVDB") or ref.startswith("URL-"):
                    # ignore OSV-DB and reference exploit for metasploit
                    continue

                if not vul:
                    try:
                        alias = Alias.objects.get(alias=ref)
                    except Alias.DoesNotExist:
                        continue

                    if not alias.vulnerability:
                        continue

                    vul = alias.vulnerability

            if not vul:
                continue

            description = record.get("description", "")
            notes = record.get("notes", {})
            source_date_published = record.get("disclosure_date")
            platform = record.get("platform")

            path = record.get("path")
            source_url = (
                f"https://github.com/rapid7/metasploit-framework/tree/master{path}" if path else ""
            )

            Exploit.objects.update_or_create(
                vulnerability=vul,
                data_source="Metasploit",
                defaults={
                    "description": description,
                    "notes": saneyaml.dump(notes),
                    "source_date_published": source_date_published,
                    "platform": platform,
                    "source_url": source_url,
                },
            )
