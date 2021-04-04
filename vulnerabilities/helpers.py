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
import json
import re

import requests
import toml
import urllib3
import yaml
from univers.versions import version_class_by_package_type

# TODO add logging here


def load_yaml(path):
    with open(path) as f:
        return yaml.safe_load(f)


def load_json(path):
    with open(path) as f:
        return json.load(f)


def load_toml(path):
    with open(path) as f:
        return toml.load(f)


def fetch_yaml(url):
    response = requests.get(url)
    return yaml.safe_load(response.content)


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


cve_regex = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
is_cve = cve_regex.match
find_all_cve = cve_regex.findall


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


def nearest_patched_package(vulnerable_packages, resolved_packages):

    if not vulnerable_packages:
        return {}

    def create_package_by_version_obj_mapping(packages, overwrite=False):
        # overwrite=True, returns version->PackageURL mapping.
        # overwrite=False, returns version->[PackageURL] mapping.
        if not packages:
            return {}

        package_by_version_obj_mapping = {}
        version_class = version_class_by_package_type[packages[0].type]
        for package in packages:
            version_object = version_class(package.version)
            if not overwrite:
                if version_object in package_by_version_obj_mapping:
                    package_by_version_obj_mapping[version_object].append(package)
                else:
                    package_by_version_obj_mapping[version_object] = [package]
            else:
                package_by_version_obj_mapping[version_object] = package

        return package_by_version_obj_mapping

    vulnerable_packages_by_version_obj = create_package_by_version_obj_mapping(vulnerable_packages)
    resolved_package_by_version_obj = create_package_by_version_obj_mapping(
        resolved_packages, overwrite=True
    )

    vulnerable_versions = list(vulnerable_packages_by_version_obj.keys())
    resolved_versions = list(resolved_package_by_version_obj.keys())

    patched_version_by_vulnerable_versions = nearest_patched_versions(
        vulnerable_versions, resolved_versions
    )

    patched_package_by_vulnerable_packages = {}
    for vulnerable_version, patched_version in patched_version_by_vulnerable_versions.items():
        for vulnerable_package in vulnerable_packages_by_version_obj[vulnerable_version]:
            patched_package_by_vulnerable_packages[vulnerable_package] = None

            if patched_version:
                patched_package = resolved_package_by_version_obj[patched_version]
                patched_package_by_vulnerable_packages[vulnerable_package] = patched_package

    return patched_package_by_vulnerable_packages


def nearest_patched_versions(vulnerable_versions, resolved_versions):
    """
    Returns a mapping of vulnerable_version -> nearest_safe_version
    """

    vulnerable_versions = sorted(vulnerable_versions)
    resolved_versions = sorted(resolved_versions)
    resolved_version_count = len(resolved_versions)
    nearest_patch_for_version = {}
    for vulnerable_version in vulnerable_versions:
        nearest_patch_for_version[vulnerable_version] = None
        if not resolved_versions:
            continue

        patched_version_index = bisect.bisect_right(resolved_versions, vulnerable_version)
        if patched_version_index >= resolved_version_count:
            continue
        nearest_patch_for_version[vulnerable_version] = resolved_versions[patched_version_index]

    return nearest_patch_for_version
