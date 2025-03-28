from datetime import datetime

import pytest

from vulnerabilities.importers import IMPORTERS_REGISTRY
from vulnerabilities.importers import nvd_importer
from vulnerabilities.models import Advisory
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipeline
from vulnerabilities.pipelines import add_advisory_id
from vulnerabilities.pipes.advisory import get_or_create_aliases


@pytest.mark.django_db
class TestAddAdvisoryPipeline:
    def test_add_advisory_id(self):
        for importer in IMPORTERS_REGISTRY.values():
            if issubclass(importer, VulnerableCodeBaseImporterPipeline):
                created_by = importer.pipeline_id
            else:
                created_by = importer.qualified_name
            aliases = get_or_create_aliases(["CVE-2021-1234"])
            advisory = Advisory.objects.create(
                unique_content_id="test-unique-content-id1",
                created_by=created_by,
                summary="TEST",
                date_collected=datetime.now(),
                url="https://test.com/source",
                advisory_id="TEST",
            )
            advisory.aliases.add(*aliases)
            add_advisory_id.AddAdvisoryID().add_advisory_id()
            advisory.refresh_from_db()
            assert advisory.advisory_id == "CVE-2021-1234"
