import pytest
from vulnerabilities import importers
from vulnerabilities.importer_yielder import IMPORTER_REGISTRY


@pytest.mark.webtest
@pytest.mark.parametrize(
    ("data_source", "config"),
    ((data["data_source"], data["data_source_cfg"]) for data in IMPORTER_REGISTRY),
)
def test_updated_advisories(data_source, config):

    if not data_source == "GitHubAPIDataSource":
        data_src = getattr(importers, data_source)
        data_src = data_src(batch_size=1, config=config)
        with data_src:
            for i in data_src.updated_advisories():
                pass
