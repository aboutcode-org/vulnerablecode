from vulnerabilities.importer import AdvisoryData
import pytest

from vulnerabilities.improver import Inference
from vulnerabilities.improvers.ai_summary_version import AISummaryImprover



@pytest.mark.django_db
def test_simple_ai_summary_version():


    advisory_data = AdvisoryData(
    summary="""Off-by-one error in the apr_brigade_vprintf function in Apache APR-util before 1.3.5
              on big-endian platforms allows remote attackers to obtain sensitive information or cause a
              denial of service (application crash) via crafted input."""
    )

    improver = AISummaryImprover()
    inference = [data.to_dict() for data in improver.get_inferences(advisory_data)]
    assert inference == Inference(
        summary=advisory_data.summary, affected_purls=[]
    )

   # assert vul.summary == """"""
