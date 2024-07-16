import os
from datetime import datetime
from unittest import mock
from unittest.mock import Mock

import pytest

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.improvers.vulnerability_kev import VulnerabilityKevImprover
from vulnerabilities.models import Alias
from vulnerabilities.models import Kev
from vulnerabilities.models import Vulnerability
from vulnerabilities.utils import load_json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data", "kev_data.json")


@pytest.mark.django_db
@mock.patch("requests.get")
def test_kev_improver(mock_get):
    advisory_data = AdvisoryData(
        aliases=["CVE-2022-21831"],
        summary="Possible code injection vulnerability in Rails / Active Storage",
        affected_packages=[],
        references=[],
        date_published=datetime.now(),
    )  # to just run the improver

    mock_response = Mock(status_code=200)
    mock_response.json.return_value = load_json(TEST_DATA)
    mock_get.return_value = mock_response

    improver = VulnerabilityKevImprover()

    # Run the improver when there is no matching aliases
    improver.get_inferences(advisory_data=advisory_data)
    assert Kev.objects.count() == 0

    v1 = Vulnerability.objects.create(vulnerability_id="VCIO-123-2002")
    v1.save()

    Alias.objects.create(alias="CVE-2021-38647", vulnerability=v1)

    # Run Kev Improver again when there are matching aliases.
    improver.get_inferences(advisory_data=advisory_data)
    assert Kev.objects.count() == 1
