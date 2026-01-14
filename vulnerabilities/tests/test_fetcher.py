#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
import time

import pytest
import responses

from vulnerabilities.fetcher import Fetcher


class TestFetcherHTTPMethods:
    """Test basic HTTP methods (GET, POST, HEAD)."""

    @responses.activate
    def test_get_success(self):
        """Test successful GET request."""
        responses.add(
            responses.GET,
            "https://example.com/api",
            json={"status": "ok"},
            status=200,
        )

        fetcher = Fetcher()
        response = fetcher.get("https://example.com/api")

        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    @responses.activate
    def test_post_success(self):
        """Test successful POST request."""
        responses.add(
            responses.POST,
            "https://example.com/api",
            json={"created": True},
            status=201,
        )

        fetcher = Fetcher()
        response = fetcher.post("https://example.com/api", json={"data": "test"})

        assert response.status_code == 201
        assert response.json() == {"created": True}

    @responses.activate
    def test_head_success(self):
        """Test successful HEAD request."""
        responses.add(
            responses.HEAD,
            "https://example.com/api",
            status=200,
        )

        fetcher = Fetcher()
        response = fetcher.head("https://example.com/api")

        assert response.status_code == 200

    @responses.activate
    def test_get_with_custom_timeout(self):
        """Test GET request with custom timeout."""
        responses.add(
            responses.GET,
            "https://example.com/api",
            json={"status": "ok"},
            status=200,
        )

        fetcher = Fetcher(timeout=60)
        response = fetcher.get("https://example.com/api")

        assert response.status_code == 200


class TestFetcherRetryLogic:
    """Test retry logic for failed requests."""

    @responses.activate
    def test_retry_on_500(self):
        """Test retry on 500 errors."""
        # First two requests fail with 500, third succeeds
        responses.add(responses.GET, "https://example.com/api", status=500)
        responses.add(responses.GET, "https://example.com/api", status=500)
        responses.add(responses.GET, "https://example.com/api", json={"ok": True}, status=200)

        fetcher = Fetcher(retry_count=3)
        response = fetcher.get("https://example.com/api")

        assert response.status_code == 200
        assert len(responses.calls) == 3

    @responses.activate
    def test_retry_exhausted(self):
        """Test that exception is raised after max retries."""
        # All requests fail with 500
        for _ in range(5):
            responses.add(responses.GET, "https://example.com/api", status=500)

        fetcher = Fetcher(retry_count=2)

        with pytest.raises(Exception):
            fetcher.get("https://example.com/api")

    @responses.activate
    def test_no_retry_on_404(self):
        """Test that 4xx errors are not retried."""
        responses.add(responses.GET, "https://example.com/api", status=404)

        fetcher = Fetcher(retry_count=3)

        with pytest.raises(Exception):
            fetcher.get("https://example.com/api")

        # Should only be called once (no retries for 404)
        assert len(responses.calls) == 1


class TestFetcherRateLimiting:
    """Test rate limiting functionality."""

    @responses.activate
    def test_rate_limiting(self):
        """Test that rate limiting delays requests."""
        # Add 3 responses
        for _ in range(3):
            responses.add(responses.GET, "https://example.com/api", status=200)

        fetcher = Fetcher(rate_limit=2.0)  # 2 requests per second

        start = time.time()
        for _ in range(3):
            fetcher.get("https://example.com/api")
        duration = time.time() - start

        # 3 requests at 2/sec should take at least 1 second
        assert duration >= 1.0

    @responses.activate
    def test_no_rate_limit(self):
        """Test that requests are not delayed when rate_limit=None."""
        # Add 3 responses
        for _ in range(3):
            responses.add(responses.GET, "https://example.com/api", status=200)

        fetcher = Fetcher(rate_limit=None)

        start = time.time()
        for _ in range(3):
            fetcher.get("https://example.com/api")
        duration = time.time() - start

        # Without rate limiting, should complete quickly (< 0.5 seconds)
        assert duration < 0.5


class TestFetcherLogging:
    """Test logging functionality."""

    @responses.activate
    def test_logging_with_standard_logger(self, caplog):
        """Test that requests are logged with standard logger."""
        responses.add(responses.GET, "https://example.com/api", status=200)

        logger = logging.getLogger(__name__)
        with caplog.at_level(logging.INFO):
            fetcher = Fetcher(logger=logger.info)
            fetcher.get("https://example.com/api")

        # Check that URL and status code are in logs
        assert "https://example.com/api" in caplog.text
        assert "200" in caplog.text

    @responses.activate
    def test_logging_with_custom_logger(self):
        """Test that requests are logged with custom logger."""
        responses.add(responses.GET, "https://example.com/api", status=200)

        log_messages = []

        def custom_logger(message, level=logging.INFO):
            log_messages.append(message)

        fetcher = Fetcher(logger=custom_logger)
        fetcher.get("https://example.com/api")

        assert len(log_messages) > 0
        assert "https://example.com/api" in log_messages[0]
        assert "200" in log_messages[0]


class TestFetcherConvenienceMethods:
    """Test convenience methods for common response types."""

    @responses.activate
    def test_fetch_json(self):
        """Test JSON parsing convenience method."""
        responses.add(
            responses.GET,
            "https://example.com/api.json",
            json={"key": "value", "nested": {"data": 123}},
        )

        fetcher = Fetcher()
        data = fetcher.fetch_json("https://example.com/api.json")

        assert data == {"key": "value", "nested": {"data": 123}}

    @responses.activate
    def test_fetch_yaml(self):
        """Test YAML parsing convenience method."""
        yaml_content = """
key: value
list:
  - item1
  - item2
nested:
  data: 123
"""
        responses.add(
            responses.GET,
            "https://example.com/data.yaml",
            body=yaml_content,
        )

        fetcher = Fetcher()
        data = fetcher.fetch_yaml("https://example.com/data.yaml")

        assert data["key"] == "value"
        assert data["list"] == ["item1", "item2"]
        assert data["nested"]["data"] == "123"  # saneyaml preserves as string

    @responses.activate
    def test_fetch_text(self):
        """Test text fetching convenience method."""
        text_content = "Hello, World!\nThis is a test."
        responses.add(
            responses.GET,
            "https://example.com/file.txt",
            body=text_content,
        )

        fetcher = Fetcher()
        text = fetcher.fetch_text("https://example.com/file.txt")

        assert text == text_content

    @responses.activate
    def test_fetch_csv(self):
        """Test CSV parsing convenience method."""
        csv_content = """name,age,city
Alice,30,NYC
Bob,25,LA
Charlie,35,SF"""
        responses.add(
            responses.GET,
            "https://example.com/data.csv",
            body=csv_content,
        )

        fetcher = Fetcher()
        csv_reader = fetcher.fetch_csv("https://example.com/data.csv")

        rows = list(csv_reader)
        assert len(rows) == 4
        assert rows[0] == ["name", "age", "city"]
        assert rows[1] == ["Alice", "30", "NYC"]
        assert rows[2] == ["Bob", "25", "LA"]


class TestFetcherStreaming:
    """Test streaming functionality for large files."""

    @responses.activate
    def test_streaming(self):
        """Test streaming for large files."""
        large_content = b"x" * 10000
        responses.add(
            responses.GET,
            "https://example.com/large.bin",
            body=large_content,
            stream=True,
        )

        fetcher = Fetcher()
        chunks = list(fetcher.stream("https://example.com/large.bin", chunk_size=1000))

        # Verify we got chunks
        assert len(chunks) > 0

        # Verify content is correct when reassembled
        reassembled = b"".join(chunks)
        assert reassembled == large_content

    @responses.activate
    def test_streaming_custom_chunk_size(self):
        """Test streaming with custom chunk size."""
        content = b"a" * 5000
        responses.add(
            responses.GET,
            "https://example.com/file.bin",
            body=content,
            stream=True,
        )

        fetcher = Fetcher()
        chunks = list(fetcher.stream("https://example.com/file.bin", chunk_size=500))

        # Verify content is correct
        assert b"".join(chunks) == content


class TestFetcherGraphQL:
    """Test GraphQL support."""

    @responses.activate
    def test_fetch_graphql_simple(self):
        """Test simple GraphQL query."""
        responses.add(
            responses.POST,
            "https://api.example.com/graphql",
            json={"data": {"user": {"name": "Alice", "id": 123}}},
            status=200,
        )

        fetcher = Fetcher()
        query = "{ user(id: 123) { name id } }"
        result = fetcher.fetch_graphql("https://api.example.com/graphql", query)

        assert result["data"]["user"]["name"] == "Alice"

    @responses.activate
    def test_fetch_graphql_with_variables(self):
        """Test GraphQL query with variables."""
        responses.add(
            responses.POST,
            "https://api.example.com/graphql",
            json={"data": {"user": {"name": "Bob", "id": 456}}},
            status=200,
        )

        fetcher = Fetcher()
        query = "query GetUser($id: Int!) { user(id: $id) { name id } }"
        variables = {"id": 456}
        result = fetcher.fetch_graphql(
            "https://api.example.com/graphql", query, variables=variables
        )

        assert result["data"]["user"]["id"] == 456

    @responses.activate
    def test_fetch_graphql_with_auth(self):
        """Test GraphQL query with authentication."""
        responses.add(
            responses.POST,
            "https://api.example.com/graphql",
            json={"data": {"viewer": {"login": "testuser"}}},
            status=200,
        )

        fetcher = Fetcher()
        query = "{ viewer { login } }"
        result = fetcher.fetch_graphql(
            "https://api.example.com/graphql", query, token="test-token-123"
        )

        assert result["data"]["viewer"]["login"] == "testuser"

        # Verify Authorization header was sent
        assert responses.calls[0].request.headers["Authorization"] == "bearer test-token-123"


class TestFetcherContextManager:
    """Test context manager protocol."""

    @responses.activate
    def test_context_manager(self):
        """Test context manager cleanup."""
        responses.add(
            responses.GET,
            "https://example.com/api",
            json={"status": "ok"},
            status=200,
        )

        with Fetcher() as fetcher:
            response = fetcher.get("https://example.com/api")
            assert response.status_code == 200

        # Session should be closed after exiting context

    @responses.activate
    def test_context_manager_with_exception(self):
        """Test context manager cleanup even when exception occurs."""
        responses.add(
            responses.GET,
            "https://example.com/api",
            status=500,
        )

        try:
            with Fetcher(retry_count=0) as fetcher:
                fetcher.get("https://example.com/api")
        except Exception:
            pass  # Expected exception

        # Session should still be closed


class TestFetcherConfiguration:
    """Test configuration options."""

    @responses.activate
    def test_custom_user_agent(self):
        """Test custom user agent configuration."""
        responses.add(
            responses.GET,
            "https://example.com/api",
            status=200,
        )

        fetcher = Fetcher(user_agent="custom-agent/1.0")
        fetcher.get("https://example.com/api")

        # Verify custom user agent was sent
        assert responses.calls[0].request.headers["User-Agent"] == "custom-agent/1.0"

    @responses.activate
    def test_default_user_agent(self):
        """Test default user agent."""
        responses.add(
            responses.GET,
            "https://example.com/api",
            status=200,
        )

        fetcher = Fetcher()
        fetcher.get("https://example.com/api")

        # Verify default user agent contains "vulnerablecode"
        user_agent = responses.calls[0].request.headers["User-Agent"]
        assert "vulnerablecode" in user_agent


class TestFetcherErrorHandling:
    """Test error handling."""

    @responses.activate
    def test_http_error_raises_exception(self):
        """Test that HTTP errors raise exceptions."""
        responses.add(
            responses.GET,
            "https://example.com/api",
            status=404,
        )

        fetcher = Fetcher(retry_count=0)

        with pytest.raises(Exception):
            fetcher.get("https://example.com/api")

    @responses.activate
    def test_network_error_raises_exception(self):
        """Test that network errors raise exceptions."""
        # responses library will raise ConnectionError for unknown URLs
        fetcher = Fetcher(retry_count=0)

        with pytest.raises(Exception):
            # Using a URL that won't be mocked
            fetcher.get("https://nonexistent-domain-12345.com")
