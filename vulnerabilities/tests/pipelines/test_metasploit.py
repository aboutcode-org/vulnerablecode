import os
from unittest import mock
from unittest.mock import Mock

import pytest

from vulnerabilities.models import Alias
from vulnerabilities.models import Exploit
from vulnerabilities.models import Vulnerability
from vulnerabilities.pipelines.enhance_with_metasploit import MetasploitImproverPipeline
from vulnerabilities.utils import load_json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "../test_data", "metasploit_improver/modules_metadata_base.json")


@pytest.mark.django_db
@mock.patch("requests.get")
def test_metasploit_improver(mock_get):
    mock_response = Mock(status_code=200)
    mock_response.json.return_value = load_json(TEST_DATA)
    mock_get.return_value = mock_response

    improver = MetasploitImproverPipeline()

    # Run the improver when there is no matching aliases
    improver.execute()
    assert Exploit.objects.count() == 0

    v1 = Vulnerability.objects.create(vulnerability_id="VCIO-123-2002")
    Alias.objects.create(alias="CVE-2007-4387", vulnerability=v1)

    # Run metasploit Improver again when there are matching aliases.
    improver.execute()
    assert Exploit.objects.count() == 1
