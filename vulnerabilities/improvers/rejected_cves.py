from typing import Iterable
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.improver import Improver, Inference
from django.db.models.query import QuerySet
from vulnerabilities.models import Advisory, Alias, Vulnerability

class RejectedCvesImprover(Improver):
    """
    Generate a translation of Advisory data - returned by the importers - into
    full confidence inferences. These are basic database relationships for
    unstructured data present in the Advisory model without any other
    information source.
    """

    @property
    def interesting_advisories(self) -> QuerySet:
        return Advisory.objects.filter(
            is_rejected = True
        )

    def get_inferences(self, advisory_data: AdvisoryData) -> Iterable[Inference]:
        if not advisory_data:
            return []
        
        aliases = advisory_data.aliases
        aliases = Alias.objects.filter(
            alias__in = aliases
        )
        vulnerabilities = Vulnerability.objects.filter(
            aliases__in = aliases
        ).distinct()

        for vuln in vulnerabilities:
            vuln.is_rejected = True
            vuln.save()
        return []
        
