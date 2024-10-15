import logging
import time
from pathlib import Path
from typing import Iterable
from django.utils import timezone
from django.db import transaction
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import json
import dateparser
import hashlib

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.models import Vulnerability, VulnerabilityReference, Alias, Weakness
from vulnerabilities.models import VulnerabilitySeverity as VulnerabilitySeverityModel
from vulnerabilities.models import Advisory
from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerabilities.utils import get_advisory_url, get_cwe_id

logger = logging.getLogger(__name__)

GITHUB_API_BASE = "https://api.github.com"
REPO_OWNER = "cisagov"
REPO_NAME = "vulnrichment"
BRANCH = "develop"

class VulnrichImporter(Importer):
    spdx_license_expression = "CC0-1.0"
    license_url = "https://github.com/cisagov/vulnrichment/blob/develop/LICENSE"
    repo_url = f"https://github.com/{REPO_OWNER}/{REPO_NAME}"
    importer_name = "Vulnrichment"

    def __init__(self):
        super().__init__()
        self.session = requests.Session()
        retries = Retry(total=5, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        self.session.mount('https://', HTTPAdapter(max_retries=retries))
        
        # Add your GitHub personal access token here
        self.github_token = "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"

    def get_with_rate_limit(self, url, params=None):
        headers = {'Authorization': f'token {self.github_token}'} if self.github_token else {}
        while True:
            response = self.session.get(url, params=params, headers=headers)
            if response.status_code == 200:
                return response
            elif response.status_code == 403 or response.status_code == 429:
                reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
                sleep_time = max(reset_time - time.time(), 0) + 1
                logger.warning(f"Rate limit exceeded. Sleeping for {sleep_time} seconds.")
                time.sleep(sleep_time)
            else:
                response.raise_for_status()

    def advisory_data(self) -> Iterable[AdvisoryData]:
        tree_url = f"{GITHUB_API_BASE}/repos/{REPO_OWNER}/{REPO_NAME}/git/trees/{BRANCH}?recursive=1"
        response = self.get_with_rate_limit(tree_url)
        tree = response.json()

        for item in tree['tree']:
            if item['type'] == 'blob' and item['path'].endswith('.json'):
                file_url = item['url']
                file_content = self.fetch_file_content(file_url)
                if file_content:
                    yield self.parse_advisory(file_content, item['path'])

    def fetch_file_content(self, file_url: str) -> dict:
        try:
            response = self.get_with_rate_limit(file_url)
            return response.json()
        except Exception as e:
            logger.error(f"Failed to fetch file content: {str(e)}")
            return None

    def parse_advisory(self, raw_data: dict, file_path: str) -> AdvisoryData:
        cve_metadata = raw_data.get("cveMetadata", {})
        cve_id = cve_metadata.get("cveId")
        
        containers = raw_data.get("containers", {})
        cna_data = containers.get("cna", {})
        adp_data = containers.get("adp", [{}])[0] if containers.get("adp") else {}

        summary = ""
        for description in cna_data.get("descriptions", []):
            if description.get("lang") == "en":
                summary = description.get("value", "")
                break

        references = []
        for ref in cna_data.get("references", []):
            reference = Reference(
                reference_id=ref.get("name"),
                url=ref.get("url"),
                reference_type=VulnerabilityReference.OTHER,
            )
            references.append(reference)

        severities = []
        metrics = adp_data.get("metrics", [])
        for metric in metrics:
            cvss_data = metric.get("cvssV3_1")
            if cvss_data:
                severity = VulnerabilitySeverity(
                    system=SCORING_SYSTEMS["cvssv3.1"],
                    value=str(cvss_data.get("baseScore")),
                    scoring_elements=cvss_data.get("vectorString"),
                )
                severities.append(severity)

        weaknesses = set()
        for problem_type in adp_data.get("problemTypes", []):
            for description in problem_type.get("descriptions", []):
                if description.get("type") == "CWE":
                    weaknesses.add(get_cwe_id(description.get("cweId")))

        date_published = cve_metadata.get("datePublished")
        if date_published:
            date_published = dateparser.parse(date_published)

        advisory_url = f"{self.repo_url}/blob/{BRANCH}/{file_path}"

        return AdvisoryData(
            aliases=[cve_id] if cve_id else [],
            summary=summary,
            references=references,
            date_published=date_published,
            weaknesses=list(weaknesses),
            url=advisory_url,
        )

    def process_advisory(self, advisory_data: AdvisoryData):
        vulnerability, advisory = process_advisory(advisory_data)
        if vulnerability and advisory:
            logger.info(f"Processed advisory for vulnerability: {vulnerability.vulnerability_id}")
        else:
            logger.info(f"Skipped existing and unchanged advisory: {advisory_data.aliases}")

def get_advisory_hash(advisory: AdvisoryData) -> str:
    content = f"{advisory.summary}{advisory.aliases}{advisory.references}{advisory.weaknesses}"
    return hashlib.md5(content.encode()).hexdigest()

@transaction.atomic
def process_advisory(advisory: AdvisoryData):
    """
    Process and save an AdvisoryData object to the database.
    """
    advisory_hash = get_advisory_hash(advisory)
    
    # Check if advisory already exists and hasn't changed
    existing_advisory = Advisory.objects.filter(aliases=advisory.aliases).first()
    if existing_advisory and existing_advisory.unique_content_id == advisory_hash:
        logger.info(f"Advisory {advisory.aliases} already exists and hasn't changed. Skipping.")
        return None, existing_advisory

    # Create or get the Vulnerability
    vulnerability = None
    for alias in advisory.aliases:
        vulnerability = Vulnerability.objects.filter(aliases__alias=alias).first()
        if vulnerability:
            break
    
    if not vulnerability:
        vulnerability_id = advisory.aliases[0] if advisory.aliases else f"VULNRICH-{advisory_hash[:8]}"
        vulnerability, created = Vulnerability.objects.get_or_create(
            vulnerability_id=vulnerability_id,
            defaults={'summary': advisory.summary}
        )
        if not created:
            # If the vulnerability already exists, update its summary
            vulnerability.summary = advisory.summary
            vulnerability.save()

    # Update aliases
    for alias in advisory.aliases:
        Alias.objects.get_or_create(alias=alias, vulnerability=vulnerability)

    # Process references
    for reference in advisory.references:
        ref, _ = VulnerabilityReference.objects.update_or_create(
            url=reference.url,
            defaults={
                'reference_id': reference.reference_id,
                'reference_type': reference.reference_type
            }
        )
        vulnerability.references.add(ref)

        # Process severities for each reference
        for severity in reference.severities:
            VulnerabilitySeverityModel.objects.update_or_create(
                reference=ref,
                scoring_system=severity.system.identifier,
                value=severity.value,
                defaults={
                    'scoring_elements': severity.scoring_elements,
                    'published_at': severity.published_at or timezone.now()
                }
            )

    # Process weaknesses
    for weakness_id in advisory.weaknesses:
        weakness, _ = Weakness.objects.get_or_create(cwe_id=weakness_id)
        vulnerability.weaknesses.add(weakness)

    # Update vulnerability
    vulnerability.summary = advisory.summary
    vulnerability.save()

    # Create or update Advisory
    advisory_obj, _ = Advisory.objects.update_or_create(
        aliases=advisory.aliases,
        defaults={
            'summary': advisory.summary,
            'references': [ref.to_dict() for ref in advisory.references],
            'date_published': advisory.date_published,
            'weaknesses': advisory.weaknesses,
            'url': advisory.url,
            'created_by': VulnrichImporter.importer_name,
            'date_collected': timezone.now(),
            'unique_content_id': advisory_hash,
        }
    )

    return vulnerability, advisory_obj