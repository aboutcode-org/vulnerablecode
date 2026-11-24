#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
import shutil
import socket
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import requests
from django.urls import reverse
from django.utils import timezone
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.models import ImpactedPackage
from vulnerabilities.models import PackageV2
from vulnerabilities.pagination import SmallResultSetPagination
from vulnerabilities.pipes.advisory import insert_advisory_v2


@pytest.mark.parametrize(
    "secure,forwarded_proto,expected_scheme",
    [
        (False, None, "http"),
        (True, None, "https"),
        (False, "https", "https"),
        (False, "http", "http"),
    ],
)
def test_pagination_links_follow_request_scheme(settings, secure, forwarded_proto, expected_scheme):
    settings.ALLOWED_HOSTS = ["testserver"]
    headers = {"HTTP_HOST": "testserver"}
    if forwarded_proto is not None:
        headers["HTTP_X_FORWARDED_PROTO"] = forwarded_proto
    request = Request(
        APIRequestFactory().get("/api/v3/packages/?page=2&page_size=1", secure=secure, **headers)
    )
    paginator = SmallResultSetPagination()
    page = paginator.paginate_queryset(["first", "second", "third"], request)
    response = paginator.get_paginated_response(page)

    assert response.data["results"] == ["second"]
    assert (
        response.data["next"]
        == f"{expected_scheme}://testserver/api/v3/packages/?page=3&page_size=1"
    )
    assert (
        response.data["previous"] == f"{expected_scheme}://testserver/api/v3/packages/?page_size=1"
    )


@pytest.fixture
def nginx_binary():
    binary = shutil.which(os.environ.get("NGINX_BINARY", "nginx"))
    if not binary or not shutil.which("openssl"):
        pytest.skip("Proxy integration tests require nginx and openssl")
    return binary


@pytest.fixture
def proxy_chain(nginx_binary, tmp_path, live_server, settings, trust_forwarded_proto):
    """Run the repository's inner Nginx behind a local HTTP/TLS outer proxy."""
    settings.ALLOWED_HOSTS = ["testserver", "localhost", "127.0.0.1"]
    certificate = tmp_path / "certificate.pem"
    key = tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
        ],
        check=True,
        capture_output=True,
    )
    sockets = [socket.socket() for _ in range(4)]
    try:
        for listener in sockets:
            listener.bind(("127.0.0.1", 0))
        inner_http, inner_https, outer_http, outer_https = [
            listener.getsockname()[1] for listener in sockets
        ]
    finally:
        for listener in sockets:
            listener.close()

    tls = f"ssl_certificate {certificate}; ssl_certificate_key {key};"
    repository = Path(__file__).resolve().parents[2]
    inner = (repository / "etc/nginx/conf.d/default.conf").read_text()
    inner = inner.replace(
        "server vulnerablecode:8000;", f"server 127.0.0.1:{urlsplit(live_server.url).port};"
    ).replace(
        "listen 80;",
        f"listen 127.0.0.1:{inner_http}; listen 127.0.0.1:{inner_https} ssl; {tls}",
    )
    if trust_forwarded_proto:
        # Configure the immediate peer exactly as an operator would in deployment.
        inner = inner.replace(
            "geo $vcio_trusted_proxy {", "geo $vcio_trusted_proxy {\n    127.0.0.1/32 1;"
        )
    config = tmp_path / "nginx.conf"
    config.write_text(
        f"pid {tmp_path}/nginx.pid; error_log stderr warn; events {{}} http {{\n"
        f"access_log off; client_body_temp_path {tmp_path}/client_body;\n"
        f"proxy_temp_path {tmp_path}/proxy; fastcgi_temp_path {tmp_path}/fastcgi;\n"
        f"uwsgi_temp_path {tmp_path}/uwsgi; scgi_temp_path {tmp_path}/scgi;\n{inner}\n"
    )
    with config.open("a") as output:
        for listener in (f"{outer_http}", f"{outer_https} ssl"):
            output.write(
                f"server {{ listen 127.0.0.1:{listener}; {tls}\n"
                f"location / {{ proxy_pass http://127.0.0.1:{inner_http};\n"
                "proxy_set_header Host $host;\n"
                "proxy_set_header X-Forwarded-Proto $scheme;\n} }\n"
            )
        output.write("}\n")

    log = tmp_path / "nginx.log"
    with log.open("w") as output:
        process = subprocess.Popen(
            [nginx_binary, "-p", f"{tmp_path}/", "-c", str(config), "-g", "daemon off;"],
            stdout=output,
            stderr=output,
        )
        try:
            deadline = time.monotonic() + 5
            while True:
                if process.poll() is not None:
                    pytest.fail(f"Nginx failed to start:\n{log.read_text()}")
                try:
                    with socket.create_connection(("127.0.0.1", inner_http), timeout=0.1):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        pytest.fail(f"Nginx did not start:\n{log.read_text()}")
                    time.sleep(0.05)
            yield {
                "http": f"http://127.0.0.1:{outer_http}",
                "https": f"https://127.0.0.1:{outer_https}",
                "direct_http": f"http://127.0.0.1:{inner_http}",
                "direct_https": f"https://127.0.0.1:{inner_https}",
                "certificate": str(certificate),
            }
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


@pytest.fixture
def package_query(transactional_db, monkeypatch):
    monkeypatch.setattr(
        "rest_framework.throttling.AnonRateThrottle.allow_request", lambda *args: True
    )
    monkeypatch.setattr(
        "vulnerabilities.throttling.PermissionBasedUserRateThrottle.allow_request",
        lambda *args: True,
    )
    purls = []
    for index in range(3):
        advisory = insert_advisory_v2(
            advisory=AdvisoryDataV2(
                summary="Pagination fixture",
                advisory_id=f"GHSA-proxy-{index}",
                url=f"https://example.com/advisory/{index}",
            ),
            pipeline_id="ghsa_pipeline_v2",
            datasource_id="ghsa",
            logger=lambda *args, **kwargs: None,
        )
        advisory._all_impacts_unfurled_at = timezone.now()
        advisory.save()
        purl = f"pkg:pypi/proxy-example@{index}.0.0"
        package = PackageV2.objects.from_purl(purl)
        impact = ImpactedPackage.objects.create(
            advisory=advisory, base_purl="pkg:pypi/proxy-example"
        )
        impact.affecting_packages.add(package)
        purls.append(purl)
    return {"purls": purls}


def query_page(proxy_chain, url, endpoint, package_query, forwarded_proto):
    headers = {"Host": "testserver", "User-Agent": "VCIO_API_AGENT"}
    if forwarded_proto is not None:
        headers["X-Forwarded-Proto"] = forwarded_proto
    response = requests.post(
        f"{url}{reverse(endpoint)}?page=2&page_size=1",
        json=package_query,
        headers=headers,
        verify=proxy_chain["certificate"],
        timeout=5,
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["count"] == 3
    assert len(data["results"]) == 1
    return data


@pytest.mark.parametrize("trust_forwarded_proto", [True])
@pytest.mark.parametrize("scheme", ["http", "https"])
@pytest.mark.parametrize("endpoint", ["package-v3-list", "advisory-v3-list"])
def test_proxy_chain_preserves_original_scheme(proxy_chain, package_query, scheme, endpoint):
    # The outer proxy must overwrite a header supplied by the original client.
    spoofed_proto = "http" if scheme == "https" else "https"
    data = query_page(proxy_chain, proxy_chain[scheme], endpoint, package_query, spoofed_proto)
    for link in ("next", "previous"):
        assert urlsplit(data[link]).scheme == scheme
        assert urlsplit(data[link]).netloc == "testserver"


@pytest.mark.parametrize(
    "trust_forwarded_proto,transport,forwarded_proto,expected_scheme",
    [
        (False, "http", "https", "http"),
        (False, "https", "http", "https"),
        (True, "http", None, "http"),
        (True, "https", None, "https"),
        (True, "http", "https", "https"),
        (True, "https", "http", "http"),
        (True, "http", "https,http", "http"),
        (True, "http", "gopher", "http"),
    ],
)
def test_direct_proxy_requests_use_validated_scheme(
    proxy_chain, package_query, transport, forwarded_proto, expected_scheme
):
    data = query_page(
        proxy_chain,
        proxy_chain[f"direct_{transport}"],
        "package-v3-list",
        package_query,
        forwarded_proto,
    )
    for link in ("next", "previous"):
        assert urlsplit(data[link]).scheme == expected_scheme
