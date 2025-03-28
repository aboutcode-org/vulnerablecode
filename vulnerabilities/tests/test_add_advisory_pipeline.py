from datetime import datetime

import pytest

from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importers import nvd_importer
from vulnerabilities.models import Advisory
from vulnerabilities.models import Alias
from vulnerabilities.pipelines import add_advisory_id
from vulnerabilities.pipes.advisory import get_or_create_aliases


@pytest.mark.django_db
class TestAddAdvisoryPipeline:
    def test_add_advisory_id(self):
        aliases = get_or_create_aliases(["CVE-2021-1234"])
        advisory = Advisory.objects.create(
            unique_content_id="test-unique-content-id1",
            created_by=nvd_importer.NVDImporterPipeline.pipeline_id,
            summary="TEST",
            date_collected=datetime.now(),
            url="https://test.com/source",
        )
        advisory.aliases.add(*aliases)
        add_advisory_id.AddAdvisoryID().add_advisory_id()
        advisory.refresh_from_db()
        assert advisory.advisory_id == "CVE-2021-1234"
