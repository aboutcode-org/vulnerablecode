#
# Copyright (c) nexB Inc. and others. All rights reserved.
# Portions Copyright (c) The Python Software Foundation
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0 and Python-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import pytest

from aboutcode.hashid import package_path_elements


@pytest.mark.parametrize(
    "purl, purl_hash",
    [
        ("pkg:maven/org.apache.commons/io", "4f"),
        ("pkg:GOLANG/google.golang.org/genproto@abcdedf#/googleapis/api/annotations/", "4a"),
        ("pkg:golang/github.com/nats-io/nats-server/v2/server@v1.2.9", "22"),
        ("pkg:bitbucket/birKenfeld/pyGments-main@244fd47e07d1014f0aed9c", "03"),
        ("pkg:github/Package-url/purl-Spec@244fd47e07d1004f0aed9c", "095"),
        ("pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie", "19"),
        (
            "pkg:docker/customer/dockerimage@sha256:244fd47e07d1004f0aed9c?repository_url=gcr.io",
            "10",
        ),
        ("pkg:gem/jruby-launcher@1.1.2?Platform=java", "1e"),
        (
            "pkg:Maven/org.apache.xmlgraphics/batik-anim@1.9.1?repositorY_url=repo.spring.io/release&classifier=sources",
            "28",
        ),
        (
            "pkg:Maven/org.apache.xmlgraphics/batik-anim@1.9.1?repositorY_url=repo.spring.io/release&extension=pom",
            "28",
        ),
        ("pkg:Maven/net.sf.jacob-project/jacob@1.14.3?type=dll&classifier=x86", "17"),
        ("pkg:npm/%40angular/animation@12.3.1", "323"),
        ("pkg:Nuget/EnterpriseLibrary.Common@6.0.1304", "63"),
        ("pkg:PYPI/Django_package@1.11.1.dev1", "00"),
        ("pkg:composer/guzzlehttp/promises@2.0.2", "1d"),
        ("pkg:Rpm/fedora/curl@7.50.3-1.fc25?Arch=i386&Distro=fedora-25", "16"),
        ("pkg:maven/HTTPClient/HTTPClient@0.3-3", "4d"),
        ("pkg:maven/mygroup/myartifact@1.0.0%20Final?mykey=my%20value", "6f"),
        ("pkg:npm/@babel/core#/googleapis/api/annotations/", "0dc"),
        ("pkg:npm/@babel/core@1.0.2#/googleapis/api/annotations/", "0dc"),
        ("pkg:npm/core@1.0.2#/googleapis/api/annotations/", "23b"),
        ("pkg:npm/core#/googleapis/api/annotations/", "23b"),
    ],
)
def test_purl_hash(purl, purl_hash):
    result_hash, *_ = package_path_elements(purl)
    assert result_hash == purl_hash
