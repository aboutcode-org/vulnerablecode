#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import csv
import logging
import threading
import time
from http import HTTPStatus
from io import StringIO
from typing import Any
from typing import Callable
from typing import Dict
from typing import Iterator
from typing import Optional

import requests
import saneyaml
import urllib3
from urllib3.util.retry import Retry

module_logger = logging.getLogger(__name__)


class Fetcher:
    """
    Centralized HTTP client with logging, retries, rate limiting, and proxy support.

    This class provides a unified interface for all network operations in VulnerableCode,
    enabling consistent logging, error handling, and configuration across all importers.

    Usage:
        # Simple request
        fetcher = Fetcher()
        response = fetcher.get("https://api.example.com/data")

        # With pipeline logging
        fetcher = Fetcher(logger=self.log, timeout=60, rate_limit=10)
        data = fetcher.fetch_json("https://api.example.com/endpoint")

        # Streaming large files
        for chunk in fetcher.stream(url, chunk_size=8192):
            f.write(chunk)

        # As context manager
        with Fetcher(logger=self.log) as f:
            data = f.fetch_json("https://api.example.com/endpoint")
    """

    def __init__(
        self,
        logger: Optional[Callable] = None,
        user_agent: Optional[str] = None,
        proxy: Optional[Dict[str, str]] = None,
        timeout: int = 30,
        retry_count: int = 3,
        retry_statuses: tuple = (500, 502, 503, 504),
        backoff_factor: float = 0.5,
        rate_limit: Optional[float] = None,
    ):
        """
        Initialize the Fetcher with configuration.

        Args:
            logger: Callable for logging (e.g., pipeline's self.log or logging.info).
                   If None, uses module logger.
            user_agent: Custom User-Agent string. If None, uses default.
            proxy: Proxy configuration dict: {"http": "...", "https": "..."}.
            timeout: Request timeout in seconds. Default: 30.
            retry_count: Maximum number of retries for failed requests. Default: 3.
            retry_statuses: HTTP status codes to retry on. Default: (500, 502, 503, 504).
            backoff_factor: Exponential backoff multiplier for retries. Default: 0.5.
            rate_limit: Maximum requests per second. None = unlimited. Default: None.
        """
        self.logger = logger if logger else module_logger.info
        self.user_agent = (
            user_agent
            if user_agent
            else "aboutcode/vulnerablecode (+https://github.com/aboutcode-org/vulnerablecode)"
        )
        self.proxy = proxy
        self.timeout = timeout
        # Treat 0 or None as unlimited rate
        self.rate_limit = rate_limit if rate_limit and rate_limit > 0 else None

        # Initialize rate limiting (token bucket algorithm)
        self._rate_limit_lock = threading.Lock()
        self._last_request_time = 0.0

        # Create requests session with retry adapter
        self._session = requests.Session()

        # Configure retry logic
        if retry_count > 0:
            retry_strategy = Retry(
                total=retry_count,
                backoff_factor=backoff_factor,
                status_forcelist=retry_statuses,
                allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"],
            )
            adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
            self._session.mount("http://", adapter)
            self._session.mount("https://", adapter)

        # Configure proxy if provided
        if self.proxy:
            self._session.proxies.update(self.proxy)

        # Set default headers
        self._session.headers.update({"User-Agent": self.user_agent})

    def _apply_rate_limit(self):
        """
        Apply rate limiting if configured.

        Uses a simple token bucket algorithm to limit requests per second.
        Thread-safe implementation using a lock.
        """
        if self.rate_limit is None:
            return

        with self._rate_limit_lock:
            current_time = time.time()
            time_since_last_request = current_time - self._last_request_time

            # Calculate minimum time between requests
            min_interval = 1.0 / self.rate_limit

            # If not enough time has passed, sleep
            if time_since_last_request < min_interval:
                sleep_time = min_interval - time_since_last_request
                time.sleep(sleep_time)

            self._last_request_time = time.time()

    def _log(self, message: str, level: str = "INFO"):
        """
        Log a message using the configured logger.

        Args:
            message: Message to log.
            level: Log level (INFO, WARNING, ERROR). Included in message for parsing.
        """
        if self.logger:
            # Simply call the logger with the message
            # The level information is already in the message format (e.g., "FAILED")
            # Pipeline loggers can parse the message if they need level information
            self.logger(message)

    def _make_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Make an HTTP request with logging and rate limiting.

        Args:
            method: HTTP method (GET, POST, HEAD, etc.).
            url: URL to request.
            **kwargs: Additional arguments passed to requests.Session.request().

        Returns:
            requests.Response: The HTTP response.

        Raises:
            requests.exceptions.HTTPError: For HTTP errors.
            requests.exceptions.RequestException: For other request errors.
        """
        # Apply rate limiting
        self._apply_rate_limit()

        # Set default timeout if not provided
        if "timeout" not in kwargs:
            kwargs["timeout"] = self.timeout

        # Make the request and measure time
        start_time = time.time()

        try:
            response = self._session.request(method, url, **kwargs)
            duration = time.time() - start_time

            # Log successful request
            self._log(
                f"[Fetcher] {method.upper()} {url} ({response.status_code} {response.reason}, {duration:.2f}s)"
            )

            # Raise HTTPError for bad status codes
            response.raise_for_status()

            return response

        except requests.exceptions.HTTPError as e:
            duration = time.time() - start_time
            self._log(
                f"[Fetcher] {method.upper()} {url} FAILED ({e.response.status_code}, {duration:.2f}s)",
                level="ERROR",
            )
            raise

        except requests.exceptions.RequestException as e:
            duration = time.time() - start_time
            self._log(
                f"[Fetcher] {method.upper()} {url} FAILED ({str(e)}, {duration:.2f}s)",
                level="ERROR",
            )
            raise

    # Core HTTP methods
    def get(self, url: str, **kwargs) -> requests.Response:
        """
        Perform a GET request.

        Args:
            url: URL to request.
            **kwargs: Additional arguments passed to requests.

        Returns:
            requests.Response: The HTTP response.
        """
        return self._make_request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        """
        Perform a POST request.

        Args:
            url: URL to request.
            **kwargs: Additional arguments passed to requests.

        Returns:
            requests.Response: The HTTP response.
        """
        return self._make_request("POST", url, **kwargs)

    def head(self, url: str, **kwargs) -> requests.Response:
        """
        Perform a HEAD request.

        Args:
            url: URL to request.
            **kwargs: Additional arguments passed to requests.

        Returns:
            requests.Response: The HTTP response.
        """
        return self._make_request("HEAD", url, **kwargs)

    # Convenience methods for common response types
    def fetch_json(self, url: str, **kwargs) -> dict:
        """
        Fetch and parse JSON from URL.

        Args:
            url: URL to fetch.
            **kwargs: Additional arguments passed to requests.

        Returns:
            dict: Parsed JSON data.

        Raises:
            ValueError: If response is not valid JSON.
        """
        response = self.get(url, **kwargs)
        return response.json()

    def fetch_yaml(self, url: str, **kwargs) -> Any:
        """
        Fetch and parse YAML from URL.

        Args:
            url: URL to fetch.
            **kwargs: Additional arguments passed to requests.

        Returns:
            Any: Parsed YAML data.
        """
        response = self.get(url, **kwargs)
        return saneyaml.load(response.content)

    def fetch_text(self, url: str, encoding: str = "utf-8", **kwargs) -> str:
        """
        Fetch text content from URL.

        Args:
            url: URL to fetch.
            encoding: Text encoding. Default: utf-8.
            **kwargs: Additional arguments passed to requests.

        Returns:
            str: Text content.
        """
        response = self.get(url, **kwargs)
        return response.content.decode(encoding)

    def fetch_csv(self, url: str, **kwargs) -> csv.reader:
        """
        Fetch and parse CSV from URL.

        Args:
            url: URL to fetch.
            **kwargs: Additional arguments passed to requests.

        Returns:
            csv.reader: CSV reader object.
        """
        response = self.get(url, **kwargs)
        content = response.content.decode("utf-8")
        return csv.reader(StringIO(content))

    def stream(self, url: str, chunk_size: int = 8192, **kwargs) -> Iterator[bytes]:
        """
        Stream large files chunk by chunk.

        Args:
            url: URL to fetch.
            chunk_size: Size of each chunk in bytes. Default: 8192.
            **kwargs: Additional arguments passed to requests.

        Yields:
            bytes: Chunks of file content.
        """
        # Force streaming mode
        kwargs["stream"] = True

        response = self._make_request("GET", url, **kwargs)

        for chunk in response.iter_content(chunk_size=chunk_size):
            if chunk:  # Filter out keep-alive chunks
                yield chunk

    def fetch_graphql(
        self,
        url: str,
        query: str,
        variables: Optional[Dict] = None,
        token: Optional[str] = None,
        **kwargs,
    ) -> dict:
        """
        Execute a GraphQL query.

        Args:
            url: GraphQL endpoint URL.
            query: GraphQL query string.
            variables: Optional query variables.
            token: Optional bearer token for authentication.
            **kwargs: Additional arguments passed to requests.

        Returns:
            dict: GraphQL response data.
        """
        headers = kwargs.pop("headers", {})

        # Add authentication if token provided
        if token:
            headers["Authorization"] = f"bearer {token}"

        # Prepare GraphQL request
        json_data = {"query": query}
        if variables:
            json_data["variables"] = variables

        response = self.post(url, json=json_data, headers=headers, **kwargs)
        return response.json()

    # Context manager support
    def __enter__(self):
        """Enter context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context manager and cleanup session."""
        if self._session:
            self._session.close()
        return False


def get_fetcher_from_settings(**overrides):
    """
    Create a Fetcher instance using Django settings.

    This helper reads FETCHER_* configuration from Django settings and creates
    a properly configured Fetcher instance. Use this in importers to get a
    centrally-configured HTTP client.

    Args:
        **overrides: Override any default settings (e.g., logger=self.log, timeout=60)

    Returns:
        Fetcher: Configured Fetcher instance.

    Example:
        # In an importer pipeline:
        fetcher = get_fetcher_from_settings(logger=self.log)
        data = fetcher.fetch_json("https://api.example.com/data")

        # With custom rate limiting:
        fetcher = get_fetcher_from_settings(logger=self.log, rate_limit=5.0)
        data = fetcher.fetch_yaml("https://example.com/advisories.yaml")
    """
    from django.conf import settings

    # Build proxy dict if configured
    proxy = {}
    if settings.FETCHER_PROXY_HTTP:
        proxy["http"] = settings.FETCHER_PROXY_HTTP
    if settings.FETCHER_PROXY_HTTPS:
        proxy["https"] = settings.FETCHER_PROXY_HTTPS

    config = {
        "user_agent": settings.FETCHER_USER_AGENT,
        "timeout": settings.FETCHER_TIMEOUT,
        "retry_count": settings.FETCHER_RETRY_COUNT,
        "backoff_factor": settings.FETCHER_RETRY_BACKOFF,
        "rate_limit": settings.FETCHER_RATE_LIMIT,
        "proxy": proxy if proxy else None,
    }

    # Apply overrides
    config.update(overrides)

    return Fetcher(**config)


# Migration Guide for Importers
# ==============================
#
# This guide shows how to migrate legacy importers to use the centralized Fetcher.
#
# Option 1: Use get_fetcher_from_settings() (RECOMMENDED)
# --------------------------------------------------------
# This automatically uses all FETCHER_* settings from Django configuration.
#
# Before (legacy):
#     response = requests.get(url)
#     data = response.json()
#
# After (with Fetcher):
#     from vulnerabilities.fetcher import get_fetcher_from_settings
#
#     fetcher = get_fetcher_from_settings(logger=self.log)
#     data = fetcher.fetch_json(url)
#
# Option 2: Use backward-compatible utils (NO CHANGES NEEDED)
# -----------------------------------------------------------
# Existing code using utils.fetch_yaml() and utils.fetch_response() will
# automatically use Fetcher internally with fallback to legacy behavior.
#
# Before:
#     from vulnerabilities.utils import fetch_yaml
#     data = fetch_yaml(url)
#
# After:
#     from vulnerabilities.utils import fetch_yaml
#     data = fetch_yaml(url)  # Now uses Fetcher internally!
#
# Option 3: Direct Fetcher instantiation (for advanced use cases)
# ---------------------------------------------------------------
# Use this when you need custom configuration not covered by settings.
#
# Before:
#     session = requests.Session()
#     session.headers.update({"Authorization": f"token {token}"})
#     response = session.get(url)
#
# After:
#     from vulnerabilities.fetcher import Fetcher
#
#     fetcher = Fetcher(
#         logger=self.log,
#         rate_limit=10.0,  # 10 requests/second
#         timeout=60,
#     )
#     response = fetcher.get(url, headers={"Authorization": f"token {token}"})
#
# Available Convenience Methods
# -----------------------------
# - fetch_json(url, **kwargs) -> dict
# - fetch_yaml(url, **kwargs) -> Any
# - fetch_text(url, encoding="utf-8", **kwargs) -> str
# - fetch_csv(url, **kwargs) -> csv.reader
# - stream(url, chunk_size=8192, **kwargs) -> Iterator[bytes]
# - fetch_graphql(url, query, variables=None, token=None, **kwargs) -> dict
#
# Benefits of Using Fetcher
# -------------------------
# - Automatic retries on 5xx errors with exponential backoff
# - Rate limiting to avoid overwhelming APIs
# - Centralized logging with [Fetcher] prefix
# - Session reuse for better performance (connection pooling)
# - Proxy support from environment variables
# - Consistent User-Agent across all importers
# - Context manager support for proper cleanup
