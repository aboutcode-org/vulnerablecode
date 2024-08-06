import logging
from typing import Iterable

from django.db.models import QuerySet
from sphinx.util import requests

from vulnerabilities.improver import Improver
from vulnerabilities.improver import Inference
from vulnerabilities.models import Advisory, VulnerabilityReference, VulnerabilityRelatedReference
from vulnerabilities.models import Alias

logger = logging.getLogger(__name__)


class MetasploitImprover(Improver):
    """
    Metasploit Improver
    """

    @property
    def interesting_advisories(self) -> QuerySet:
        # TODO Modify Metasploit Improver to iterate over the vulnerabilities alias, not the advisory
        return [Advisory.objects.first()]

    def get_inferences(self, advisory_data) -> Iterable[Inference]:
        """
        """

        metasploit_modules_url = (
            "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
        )
        response = requests.get(metasploit_modules_url)
        metasploit_data = response.json()
        if response.status_code != 200:
            logger.error(
                f"Failed to fetch the Metasploit Exploits: {metasploit_modules_url}"
            )
            return []
        try:
            for file_path, record in metasploit_data.items():
                file_url = f"https://github.com/rapid7/metasploit-framework/tree/master/modules/{file_path}"

                ref_list = []
                vulnerabilities = set()
                for ref in record.get("references"):
                    if ref.startswith("URL-"):
                        ref_list.append(ref[4::])

                    alias = Alias.objects.get_or_none(alias=ref)

                    if not alias:
                        continue

                    vul = alias.vulnerability

                    if not vul:
                        continue

                    ref, created = VulnerabilityReference.objects.update_or_create(
                        reference_id=alias,
                        reference_type=VulnerabilityReference.EXPLOIT,
                        defaults={"url": file_url},
                    )

                    if created:
                        VulnerabilityRelatedReference.objects.create(
                            vulnerability=vul,
                            reference=ref,
                        )
                    vulnerabilities.add(vul)

                for vul in vulnerabilities:
                    for ref in ref_list:
                        ref_obj, created = VulnerabilityReference.objects.update_or_create(
                            reference_id=ref,
                            defaults={"url": file_url},
                        )

                        if created:
                            VulnerabilityRelatedReference.objects.create(
                                vulnerability=vul,
                                reference=ref_obj,
                            )
        except Exception as e:
            logger.error(e)

        return []
