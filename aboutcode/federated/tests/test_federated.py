#
# Copyright (c) AboutCode and others. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about our open source projects.
#

from pathlib import Path

import pytest
import requests
from packageurl import PackageURL

from aboutcode.federated import DataCluster
from aboutcode.federated import DataDirectory
from aboutcode.federated import DataFederation
from aboutcode.federated import DataMaintainer
from aboutcode.federated import DataRepository
from aboutcode.federated import GitRepo
from aboutcode.federated import PurlTypeConfig
from aboutcode.federated import as_purl
from aboutcode.federated import build_direct_federation_config_file_url
from aboutcode.federated import cluster_preset
from aboutcode.federated import compute_purl_hash
from aboutcode.federated import get_core_purl
from aboutcode.federated import is_valid_power_of_two
from aboutcode.federated import package_path_elements
from aboutcode.federated import percent_quote_more
from pickle import FALSE

TEST_DATA = Path(__file__).parent / "test_data"

REGEN =False


def test_DataFederation_from_dict_and_to_dict(tmp_path):
    data = {
        "name": "fed",
        "remote_root_url": "https://example.com",
        "description": "desc",
        "documentation_url": "doc",
        "data_license": "MIT",
        "maintainers": [{"name": "x"}],
        "data_clusters": [],
    }
    fed = DataFederation.from_dict(data, local_root_dir=tmp_path)
    d = fed.to_dict()
    assert "name" in d


def test_DataFederation_basic(tmp_path):
    f = DataFederation(
        name="fed",
        local_root_dir=tmp_path,
        remote_root_url="https://foo.com",
    )
    assert f.local_config_dir == tmp_path / "fed"
    assert str(f.local_config_file).endswith("fed/aboutcode-federated-config.yml")
    assert isinstance(f.config_repo, GitRepo)


def test_DataFederation_remote_config_file_url():
    url = DataFederation.remote_config_file_url(
        remote_root_url="https://github.com/org", federation_name="fed"
    )
    assert url == "https://github.com/org/fed/raw/refs/heads/main/aboutcode-federated-config.yml"


def test_DataFederation_load(tmp_path):
    # setup
    cfg_file = tmp_path / "fed" / DataFederation.CONFIG_FILENAME
    cfg_file.parent.mkdir(parents=True)
    cfg_file.write_text("name: fed\n")

    # test
    fed = DataFederation.load("fed", tmp_path)
    assert fed.name == "fed"
    assert fed.data_clusters == []


def test_DataFederation_from_url(monkeypatch):

    class Response:
        ok = True
        text = "name: fed\n" "remote_root_url: https://github.com/org\n"

    monkeypatch.setattr(requests, "get", lambda url, headers: Response())
    fed = DataFederation.from_url(name="fed", remote_root_url="https://github.com/org")
    assert fed.name == "fed"
    assert fed.data_clusters == []


def test_DataCluster_from_dict():
    data = {
        "data_kind": "x",
        "datafile_path_template": "{/foo}/data.json",
        "purl_type_configs": [],
    }
    DataCluster.from_dict(data)


def test_PurlTypeConfig_basic():
    ptc = PurlTypeConfig(purl_type="npm", number_of_repos=4, number_of_dirs=16)
    assert ptc.numbers_of_dirs_per_repo == 4
    assert len(ptc.hashids) == 16
    repos = list(ptc.get_repos(data_kind="purls"))
    assert len(repos) == 4
    assert all(len(r.data_directories) == 4 for r in repos)
    assert all(isinstance(r, DataRepository) for r in repos)


def test_PurlTypeConfig_validates_settings():
    with pytest.raises(TypeError):
        PurlTypeConfig(purl_type="npm", number_of_repos=3, number_of_dirs=16)
    with pytest.raises(TypeError):
        PurlTypeConfig(purl_type="npm", number_of_repos=4, number_of_dirs=0)
    with pytest.raises(TypeError):
        PurlTypeConfig(purl_type="npm", number_of_repos=8, number_of_dirs=4)


def test_PurlTypeConfig_defaults_and_presets():
    d = PurlTypeConfig.default_config()
    assert isinstance(d, PurlTypeConfig)

    assert d.purl_type == "default"
    large = PurlTypeConfig.large_size_configs()
    assert all(isinstance(ptc, PurlTypeConfig) for ptc in large)

    medium = PurlTypeConfig.medium_size_configs()
    assert all(isinstance(ptc, PurlTypeConfig) for ptc in medium)

    small = PurlTypeConfig.small_size_configs()
    assert all(isinstance(ptc, PurlTypeConfig) for ptc in small)


def test_DataRepository_from_hashids():
    repo = DataRepository.from_hashids("purls", "npm", ["0000", "0001"])
    assert repo.name == "purls-npm-0000"
    assert len(repo.data_directories) == 2


def test_DataDirectory():
    d = DataDirectory(purl_type="pypi", hashid="0256")
    assert d.name == "pypi-0256"


def test_DataDirectory_with_local_dir(tmp_path):
    d = DataDirectory(purl_type="npm", hashid="0010", local_root_dir=tmp_path)
    assert d.name == "npm-0010"
    path = d.local_dir_path(local_root_dir=tmp_path, repo_name="repo")
    assert str(path).endswith("repo/npm-0010")


def test_DataMaintainer():
    m = DataMaintainer(name="John", email="a@b.com", url="https://x.com")
    assert m.to_dict() == dict(name="John", email="a@b.com", url="https://x.com")

    m = DataMaintainer(name="John")
    assert m.to_dict() == dict(name="John", email=None, url=None)


def test_build_direct_federation_config_file_url():
    url = build_direct_federation_config_file_url(
        remote_root_url="https://github.com/aboutcode-data",
        federation_name="aboutcode-data",
        config_filename="aboutcode-federated-config.yml",
    )
    assert (
        url
        == "https://github.com/aboutcode-data/aboutcode-data/raw/refs/heads/main/aboutcode-federated-config.yml"
    )


def test_compute_purl_hash():
    p1 = "pkg:pypi/univers@1.0.0"
    h1 = compute_purl_hash(p1)
    p2 = "pkg:pypi/univers@2.0.0"
    h2 = compute_purl_hash(p2)
    assert h1 == h2
    assert h1 == "0145"


def test_is_valid_power_of_two():
    assert not is_valid_power_of_two(0)
    assert is_valid_power_of_two(1)
    assert is_valid_power_of_two(2)
    assert not is_valid_power_of_two(3)
    assert not is_valid_power_of_two(3, max_value=256)
    assert is_valid_power_of_two(4, max_value=4)
    assert is_valid_power_of_two(1024)
    assert not is_valid_power_of_two(1024, max_value=256)
    assert not is_valid_power_of_two(2048)
    assert not is_valid_power_of_two(2048, max_value=1024)
    assert is_valid_power_of_two(8192, max_value=8192)


def test_percent_quote_more():
    assert percent_quote_more("abc/def") == "abc%2Fdef"
    assert percent_quote_more("abc%2Fdef") == "abc%2Fdef"
    assert percent_quote_more("abc:def") == "abc%3Adef"
    assert percent_quote_more("") == ""


def test_as_purl():
    p = "pkg:pypi/example@1.0.0?file_name=foo.bar&key=value#sub/path"
    purl = as_purl(p)
    assert isinstance(purl, PackageURL)
    assert purl.to_string() == p

    purl2 = as_purl(purl)
    assert isinstance(purl2, PackageURL)
    assert purl2 == purl

    with pytest.raises(ValueError):
        purl = as_purl(123)

    with pytest.raises(ValueError):
        purl = as_purl("foo")


def test_get_core_purl():
    p = "pkg:pypi/example@1.0.0?file_name=foo.bar&key=value#sub/path"
    core = get_core_purl(p)
    assert core.to_string() == "pkg:pypi/example"


def test_package_path_elements():
    purl = "pkg:pypi/license_expression@30.3.1"
    phash, core, ver, extra = package_path_elements(purl)
    assert isinstance(phash, str)
    assert "pypi" in core
    assert ver == "30.3.1"
    assert extra == ""
    purl2 = "pkg:pypi/license_expression@30.3.1?foo=bar#sub/path"
    phash, core, ver, extra = package_path_elements(purl2)
    assert "%3D" in extra


PURLS_AND_HASHES = [
    ("pkg:maven/org.apache.commons/io", "0604"),
    ("pkg:GOLANG/google.golang.org/genproto@abcdedf#/googleapis/api/annotations/", "0643"),
    ("pkg:golang/google.golang.org/genproto", "0643"),
    ("pkg:golang/github.com/nats-io/nats-server/v2/server@v1.2.9", "0107"),
    ("pkg:bitbucket/birKenfeld/pyGments-main@244fd47e07d1014f0aed9c", "0913"),
    ("pkg:github/Package-url/purl-Spec@244fd47e07d1004f0aed9c", "0694"),
    ("pkg:github/package-url/purl-spec", "0694"),
    ("pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie", "0320"),
    ("pkg:docker/customer/dockerimage@sha256:244fd47e07d1004f0aed9c?repository_url=gcr.io", "0387"),
    ("pkg:gem/jruby-launcher@1.1.2?Platform=java", "0884"),
    (
        "pkg:Maven/org.apache.xmlgraphics/batik-anim@1.9.1?repositorY_url=repo.spring.io/release&classifier=sources",
        "0758",
    ),
    (
        "pkg:Maven/org.apache.xmlgraphics/batik-anim@1.9.1?repositorY_url=repo.spring.io/release&extension=pom",
        "0758",
    ),
    ("pkg:maven/org.apache.xmlgraphics/batik-anim", "0758"),
    ("pkg:Maven/net.sf.jacob-project/jacob@1.14.3?type=dll&classifier=x86", "0221"),
    ("pkg:maven/net.sf.jacob-project/jacob", "0221"),
    ("pkg:npm/%40angular/animation@12.3.1", "1001"),
    ("pkg:Nuget/EnterpriseLibrary.Common@6.0.1304", "0820"),
    ("pkg:PYPI/Django-package@1.11.1.dev1", "0603"),
    ("pkg:pypi/django_package", "0603"),
    ("pkg:composer/guzzlehttp/promises@2.0.2", "0925"),
    ("pkg:Rpm/fedora/curl@7.50.3-1.fc25?Arch=i386&Distro=fedora-25", "0832"),
    ("pkg:rpm/fedora/curl@7.50.3-1.fc25?Arch=i386&Distro=fedora-25", "0832"),
    ("pkg:maven/HTTPClient/HTTPClient@0.3-3", "0084"),
    ("pkg:maven/mygroup/myartifact@1.0.0%20Final?mykey=my%20value", "0566"),
    ("pkg:npm/@babel/core#/googleapis/api/annotations/", "0985"),
    ("pkg:npm/@babel/core@1.0.2#/googleapis/api/annotations/", "0985"),
    ("pkg:npm/core@1.0.2#/googleapis/api/annotations/", "0775"),
    ("pkg:npm/core#/googleapis/api/annotations/", "0775"),
]


@pytest.mark.parametrize("purl, purl_hash", PURLS_AND_HASHES)
def test_purl_hash(purl, purl_hash):
    result_hash, *_ = package_path_elements(purl)
    assert result_hash == purl_hash


def test_federation_with_all_cluster_preset():
    df = DataFederation(name="foo", data_clusters=sorted(cluster_preset().values()))
    local_root_dir = TEST_DATA / "all-presets"
    if False:
        df.local_root_dir = local_root_dir
        df.dump() 
    df2 = DataFederation.load(name="foo", local_root_dir=local_root_dir)
    assert df.to_dict() == df2.to_dict()
