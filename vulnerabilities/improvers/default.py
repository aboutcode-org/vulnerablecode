from typing import List

from vulnerabilities.data_source import AdvisoryData
from vulnerabilities.data_inference import Inference
from vulnerabilities.data_inference import Improver
from vulnerabilities.data_inference import MAX_CONFIDENCE
from vulnerabilities.models import Advisory


class DefaultImprover(Improver):
    def inferences(self) -> List[Inference]:
        advisories = Advisory.objects.filter(
            source="vulnerabilities.importers.nginx.NginxDataSource"
        )
        return [
            Inference(
                advisory_data=AdvisoryData.fromJson(advisory.data),
                source=advisory.source,
                confidence=MAX_CONFIDENCE,
            )
            for advisory in advisories
        ]
