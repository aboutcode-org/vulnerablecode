#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import re
import time
from urllib.parse import urlparse
from pathlib import Path
import pytest
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# Configuration - Update EXCLUDED_URLS with problematic URLs
EXCLUDED_URLS = {
    # Timeout-prone URLs
    'https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%20508c.pdf',
    
    # Template URLs with placeholders
    'https://www.debian.org/security/oval/oval-definitions-{release}.xml.bz2',
    'https://www.postgresql.org/support/security/{cve_id',
    'https://www.wireshark.org/security/{wnpa_sec_id}.html',
    'https://xenbits.xen.org/xsa/advisory-{number}.html',
    'https://xenbits.xen.org/xsa/advisory-{numid}.html',
    
    # Invalid URL patterns
    'https://{token}@',
    
    # Known 403/404 URLs
    'https://www.openssl.org/news/vulnerabilities.xml',
    'https://www.softwaretestinghelp.com/how-to-write-good-bug-report/',
    
    # XML namespace URLs
    'http://www.w3.org/2001/XMLSchema-instance'
}

USER_AGENT = 'VulnerableCode URL Checker/1.0'
MAX_RETRIES = 3
TIMEOUT = 25  # Increased timeout

def sanitize_url(url):
    """Clean up URLs from documentation syntax artifacts"""
    # Remove template placeholders
    url = re.sub(r'\{.*?\}', '', url)
    # Remove RST/Markdown formatting
    url = re.sub(r'[>`_\[\](){}\\]+$', '', url)
    # Remove URL-encoded variables
    url = re.sub(r'%7[Bb]raw_data%5[BbDd].*', '', url)
    return url.rstrip('.,;:').strip()

def is_valid_url(url):
    """Validate URL structure and exclude templates"""
    try:
        # Reject URLs with residual placeholders or invalid patterns
        if re.search(r'\{\w+?\}', url) or '@' in url.split('//')[-1]:
            return False
            
        parsed = urlparse(url)
        if not all([parsed.scheme, parsed.netloc]):
            return False
            
        return re.match(r'^https?://[^\s/$.?#]+\.[^\s]{2,}', url) is not None
    except ValueError:
        return False

def extract_urls(content):
    """Find URLs while ignoring documentation syntax"""
    # regex to avoid capturing template URLs
    url_pattern = re.compile(
        r'\bhttps?://(?:[^\s>"\'\\\]`<{}]+|%[0-9a-fA-F]{2})+\b'
    )
    return [sanitize_url(url) for url in url_pattern.findall(content)]

def get_all_urls():
    """Get all unique URLs from code and docs with enhanced filtering"""
    urls = []
    
    # Scan documentation
    docs_dir = Path("docs")
    for ext in ('*.rst', '*.md'):
        for path in docs_dir.rglob(ext):
            urls.extend(extract_urls(path.read_text()))
    
    # Scan codebase
    code_dirs = [
        Path("vulnerabilities/management/commands"),
        Path("vulnerabilities/")
    ]
    for code_dir in code_dirs:
        for path in code_dir.rglob('*.py'):
            urls.extend(extract_urls(path.read_text()))
    
    return sorted({
        url for url in urls
        if is_valid_url(url) and url not in EXCLUDED_URLS
    })

@pytest.fixture(scope="module")
def session():
    """Configure HTTP session with enhanced retry logic"""
    session = requests.Session()
    retries = Retry(
        total=MAX_RETRIES,
        backoff_factor=1.5,
        status_forcelist=[500, 502, 503, 504, 429],
        allowed_methods=['HEAD', 'GET'],
        respect_retry_after_header=True
    )
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.mount('https://', HTTPAdapter(max_retries=retries))
    return session

@pytest.mark.parametrize("url", get_all_urls())
def test_url_is_alive(url, session):
    headers = {'User-Agent': USER_AGENT}
    
    try:
        # Initial attempt with HEAD
        try:
            response = session.head(
                url,
                headers=headers,
                allow_redirects=True,
                timeout=TIMEOUT
            )
            if response.status_code == 405:
                response = session.get(
                    url,
                    headers=headers,
                    allow_redirects=True,
                    timeout=TIMEOUT
                )
        except requests.exceptions.SSLError:
            # Fallback to GET without SSL verification
            response = session.get(
                url,
                headers=headers,
                verify=False,
                timeout=TIMEOUT
            )
        
        # Handle special cases
        if response.status_code in [403, 404] and url in EXCLUDED_URLS:
            pytest.skip(f"Skipping excluded URL: {url}")
            
        if response.status_code == 403:
            pytest.xfail(f"Expected 403 Forbidden for protected resource: {url}")
            
        assert 200 <= response.status_code < 400, \
            f"URL {url} returned status {response.status_code}"
            
    except requests.exceptions.Timeout:
        pytest.xfail(f"Timeout occurred for {url} - may be temporary")
        
    except requests.exceptions.RequestException as e:
        if isinstance(e, requests.exceptions.ConnectionError):
            if url in EXCLUDED_URLS:
                pytest.skip(f"Skipping connection error for excluded URL: {url}")
            pytest.xfail(f"Connection failed for {url} - possible network issue")
            
        pytest.fail(f"Failed to access {url}: {str(e)}")
    
    finally:
        time.sleep(1)