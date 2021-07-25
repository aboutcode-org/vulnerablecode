# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import bisect
import dataclasses
import json
import re
from typing import List
from typing import Optional
from typing import Tuple

import requests
import saneyaml
import toml
import urllib3
from packageurl import PackageURL
from univers.versions import version_class_by_package_type

# TODO add logging here

cve_regex = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
is_cve = cve_regex.match
find_all_cve = cve_regex.findall


@dataclasses.dataclass(order=True, frozen=True)
class AffectedPackage:
    vulnerable_package: PackageURL
    patched_package: Optional[PackageURL] = None


def load_yaml(path):
    with open(path) as f:
        return saneyaml.load(f)


def load_json(path):
    with open(path) as f:
        return json.load(f)


def load_toml(path):
    with open(path) as f:
        return toml.load(f)


def fetch_yaml(url):
    response = requests.get(url)
    return saneyaml.load(response.content)


# FIXME: this is NOT how etags work .
# We should instead send the proper HTTP header
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-None-Match
# and integrate this finely in the processing as this typically needs to use
# streaming=True requests, and proper handling of the HTTP return code
# In all cases this ends up being a single request, not a HEADD followed
# by another real request
def create_etag(data_src, url, etag_key):
    """
    Etags are like hashes of web responses. For a data source `data_src`,
    we maintain (url, etag) mappings in the DB.  `create_etag`  creates
    (`url`, etag) pair. If a (`url`, etag) already exists then the code
    skips processing the response further to avoid duplicate work.

    `etag_key` is the name of header which contains the etag for the url.
    """
    etag = requests.head(url).headers.get(etag_key)
    if not etag:
        return True

    elif url in data_src.config.etags:
        if data_src.config.etags[url] == etag:
            return False

    data_src.config.etags[url] = etag
    return True


def contains_alpha(string):
    """
    Return True if the input 'string' contains any alphabet
    """

    return any([c.isalpha() for c in string])


def requests_with_5xx_retry(max_retries=5, backoff_factor=0.5):
    """
    Returns a requests sessions which retries on 5xx errors with
    a backoff_factor
    """
    retries = urllib3.util.Retry(
        total=max_retries,
        backoff_factor=backoff_factor,
        raise_on_status=True,
        status_forcelist=range(500, 600, 1),
    )
    adapter = requests.adapters.HTTPAdapter(max_retries=retries)
    session = requests.Session()
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def nearest_patched_package(
    vulnerable_packages: List[PackageURL], resolved_packages: List[PackageURL]
) -> List[AffectedPackage]:
    class PackageURLWithVersionComparator:
        """
        This class is used to  get around bisect module's lack of supplying custom
        compartor. Get rid of this once we use python 3.10 which supports this.
        See https://github.com/python/cpython/pull/20556
        """

        def __init__(self, package):
            self.package = package
            self.version_object = version_class_by_package_type[package.type](package.version)

        def __eq__(self, other):
            return self.version_object == other.version_object

        def __lt__(self, other):
            return self.version_object < other.version_object

    vulnerable_packages = sorted(
        [PackageURLWithVersionComparator(package) for package in vulnerable_packages]
    )
    resolved_packages = sorted(
        [PackageURLWithVersionComparator(package) for package in resolved_packages]
    )

    resolved_package_count = len(resolved_packages)
    affected_package_with_patched_package_objects = []

    for vulnerable_package in vulnerable_packages:
        patched_package_index = bisect.bisect_right(resolved_packages, vulnerable_package)
        patched_package = None
        if patched_package_index < resolved_package_count:
            patched_package = resolved_packages[patched_package_index].package

        affected_package_with_patched_package_objects.append(
            AffectedPackage(
                vulnerable_package=vulnerable_package.package, patched_package=patched_package
            )
        )

    return affected_package_with_patched_package_objects


def split_markdown_front_matter(text: str) -> Tuple[str, str]:
    r"""
    Return a tuple of (front matter, markdown body) strings split from ``text``.
    Each can be an empty string.

    >>> text='''---
    ... title: DUMMY-SECURITY-2019-001
    ... description: Incorrect access control.
    ... cves: [CVE-2042-1337]
    ... ---
    ... # Markdown starts here
    ... '''
    >>> split_markdown_front_matter(text)
    ('title: DUMMY-SECURITY-2019-001\ndescription: Incorrect access control.\ncves: [CVE-2042-1337]', '# Markdown starts here')
    """
    # The doctest contains \n and for the sake of clarity I chose raw strings than escaping those.
    lines = text.splitlines()
    if lines[0] == "---":
        lines = lines[1:]
        text = "\n".join(lines)
        frontmatter, _, markdown = text.partition("\n---\n")
        return frontmatter, markdown

    return "", text
