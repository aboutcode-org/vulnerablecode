#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import bisect
import csv
import dataclasses
import hashlib
import json
import logging
import os
import re
import urllib.request
from collections import defaultdict
from functools import total_ordering
from http import HTTPStatus
from typing import List
from typing import Optional
from typing import Tuple
from typing import Union
from unittest.mock import MagicMock
from urllib.parse import urljoin

import dateparser
import requests
import saneyaml
import toml
import urllib3
from cwe2.database import Database
from cwe2.database import InvalidCWEError
from packageurl import PackageURL
from packageurl.contrib.django.utils import without_empty_values
from univers.version_range import RANGE_CLASS_BY_SCHEMES
from univers.version_range import AlpineLinuxVersionRange
from univers.version_range import NginxVersionRange
from univers.version_range import VersionRange

from aboutcode.hashid import build_vcid

logger = logging.getLogger(__name__)

cve_regex = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}", re.IGNORECASE)
is_cve = cve_regex.match
find_all_cve = cve_regex.findall
cwe_regex = r"CWE-\d+"

commit_regex = re.compile(r"\b[0-9a-f]{5,40}\b", re.IGNORECASE)
is_commit = commit_regex.fullmatch


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


# FIXME: Remove this entirely after complete importer-improver migration
create_etag = MagicMock()


def split_markdown_front_matter(text: str) -> Tuple[str, str]:
    """
    Return a tuple of (front matter, markdown body) strings split from a
    ``text`` string. Each can be an empty string. This is used when security
    advisories are provided in this format.
    """
    lines = text.splitlines()
    if not lines:
        return "", ""

    if lines[0] == "---":
        lines = lines[1:]
        text = "\n".join(lines)
        frontmatter, _, markdown = text.partition("\n---\n")
        return frontmatter, markdown

    return "", text


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
    retries = urllib3.Retry(
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


@total_ordering
class VersionedPackage:
    """
    A PackageURL with a Version class.
    This class is used to  get around bisect module's lack of supplying custom
    comparator. Get rid of this once we use python 3.10 which supports this.
    See https://github.com/python/cpython/pull/20556
    """

    def __init__(self, purl: PackageURL):
        self.purl = purl
        vrc = RANGE_CLASS_BY_SCHEMES.get(purl.type)
        self.version = vrc.version_class(purl.version)

    def __eq__(self, other):
        return self.version == other.version

    def __lt__(self, other):
        return self.version < other.version


def update_purl_version(purl, version):
    """
    Return a new PackageURL derived from the ``purl`` PackageURL object or string
    with the new version.

    For example::
    >>> purl = PackageURL.from_string("pkg:generic/this@1.2.3")
    >>> evolved = PackageURL.from_string("pkg:generic/this@2.2.3")
    >>> update_purl_version(purl, version="2.2.3") == evolved
    True
    """
    purl = normalize_purl(purl=purl)
    if not version:
        return purl
    merged = purl.to_dict()
    merged["version"] = version
    return normalize_purl(PackageURL(**merged))


def nearest_patched_package(
    vulnerable_packages: List[PackageURL], resolved_packages: List[PackageURL]
) -> List[AffectedPackage]:
    """
    Return a list of Affected Packages for each Patched package.
    """

    vulnerable_packages = sorted([VersionedPackage(package) for package in vulnerable_packages])
    resolved_packages = sorted([VersionedPackage(package) for package in resolved_packages])

    resolved_package_count = len(resolved_packages)
    affected_package_with_patched_package_objects = []

    for vulnerable_package in vulnerable_packages:
        patched_package_index = bisect.bisect_right(resolved_packages, vulnerable_package)
        patched_package = None
        if patched_package_index < resolved_package_count:
            patched_package = resolved_packages[patched_package_index]

        affected_package_with_patched_package_objects.append(
            AffectedPackage(
                vulnerable_package=vulnerable_package.purl,
                patched_package=patched_package.purl if patched_package else None,
            )
        )

    return affected_package_with_patched_package_objects


# TODO: Replace this with combination of @classmethod and @property after upgrading to python 3.9
class classproperty(object):
    def __init__(self, fget):
        self.fget = fget

    def __get__(self, owner_self, owner_cls):
        return self.fget(owner_cls)


def get_item(entity: Union[dict, list], *attributes):
    """
    Return `item` by going through all the `attributes` present in the `dictionary/list`

    Do a DFS for the `item` in the `dictionary/list` by traversing the `attributes`
    and return None if can not traverse through the `attributes`
    For example:
    >>> assert get_item({'a': {'b': {'c': 'd'}}}, 'a', 'b', 'c') == 'd'
    >>> assert get_item({'a': [{'b': {'c': 'd'}}]}, 'a', 0, 'b') == {'c': 'd'}
    >>> assert get_item(['b', ['c', ['d']]], 1, 1, 0) == 'd'
    >>> get_item({'a': {'b': {'c': 'd'}}}, 'a', 'b', 'c')
    'd'
    >>> assert(get_item({'a': {'b': {'c': 'd'}}}, 'a', 'b', 'e')) == None
    """
    for attribute in attributes:
        if not entity:
            return
        if not isinstance(entity, (dict, list)):
            logger.error(f"Entity must be of type `dict` or `list` not {type(entity)}")
            return
        if isinstance(entity, dict) and attribute not in entity:
            logger.error(f"Missing attribute {attribute} in {entity}")
            return
        if isinstance(entity, list) and not isinstance(attribute, int):
            logger.error(f"List indices must be integers not {type(attribute)}")
            return
        if isinstance(entity, list) and len(entity) <= attribute:
            logger.error(f"Index {attribute} out of range for {entity}")
            return

        entity = entity[attribute]
    return entity


class GitHubTokenError(Exception):
    pass


class GraphQLError(Exception):
    pass


def fetch_github_graphql_query(graphql_query: dict):
    """
    Return results from calling the Github graphql API with the ``graphql_query`` mapping.
    Raise a GitHubTokenError if the "GH_TOKEN" environment variable is not set.
    Raise a GraphQLError on query errors.
    """
    gh_token = os.environ.get("GH_TOKEN", None)
    # graphql api cannot work without api token
    if not gh_token:
        msg = "Cannot call GitHub API without a token set in the GH_TOKEN environment variable."
        logger.error(msg)
        raise GitHubTokenError(msg)

    response = _get_gh_response(gh_token=gh_token, graphql_query=graphql_query)

    if not response:
        msg = "No response received from GitHub API."
        logger.error(msg)
        raise GraphQLError(msg)

    message = response.get("message")
    if message and message == "Bad credentials":
        raise GitHubTokenError(f"Invalid GitHub token: {message}")

    errors = response.get("errors")
    if errors:
        raise GraphQLError(errors)

    return response


def _get_gh_response(gh_token, graphql_query):
    """
    Convenience function to easy mocking in tests
    """
    endpoint = "https://api.github.com/graphql"
    headers = {"Authorization": f"bearer {gh_token}"}
    try:
        return requests.post(endpoint, headers=headers, json=graphql_query).json()
    except Exception as e:
        logger.error(f"Failed to fetch data from GitHub GraphQL API: {e}")


def dedupe(original: List) -> List:
    """
    Remove all duplicate items and return a new list preserving ordering
    >>> dedupe(["z","i","a","a","d","d"])
    ['z', 'i', 'a', 'd']
    """
    return list(dict.fromkeys(original))


def get_affected_packages_by_patched_package(
    affected_packages: List[AffectedPackage],
):
    """
    Return a mapping of list of vulnerable purls keyed by
    purl which fix those vulnerable package.
    """
    affected_packages_by_patched_package = defaultdict(list)
    for package in affected_packages:
        if package.vulnerable_package:
            affected_packages_by_patched_package[package.patched_package].append(
                package.vulnerable_package
            )
    return affected_packages_by_patched_package


# This code has been vendored from scancode.
# https://github.com/nexB/scancode-toolkit/blob/aba31126dcb3ab57f2b885090f7145f69b67351a/src/packagedcode/utils.py#L111
def build_description(summary, description):
    """
    Return a description string from a summary and description
    """
    summary = (summary or "").strip()
    description = (description or "").strip()

    if not description:
        description = summary
    else:
        if summary and summary not in description:
            description = "\n".join([summary, description])

    return description


def get_reference_id(url: str):
    """
    Return the reference id from a URL
    For example:
    >>> get_reference_id("https://github.com/advisories/GHSA-c9hw-wf7x-jp9j")
    'GHSA-c9hw-wf7x-jp9j'
    """
    _url, _, ref_id = url.strip("/").rpartition("/")
    return ref_id


def resolve_version_range(
    affected_version_range: VersionRange,
    package_versions: List[str],
    ignorable_versions: List[str] = tuple(),
) -> Tuple[List[str], List[str]]:
    """
    Given an affected version range and a list of `package_versions`, resolve
    which versions are in this range and return a tuple of two lists of
    `affected_versions` and `unaffected_versions`.
    """
    if not affected_version_range:
        logger.error(f"affected version range is {affected_version_range!r}")
        return [], []
    affected_versions = []
    unaffected_versions = []
    for package_version in package_versions or []:
        if package_version in ignorable_versions:
            continue
        # Remove whitespace
        package_version = package_version.replace(" ", "")
        # Remove leading 'v'
        package_version = package_version.lstrip("vV")
        try:
            version = affected_version_range.version_class(package_version)
        except Exception:
            logger.error(f"Could not parse version {package_version!r}")
            continue
        try:
            if version in affected_version_range:
                affected_versions.append(package_version)
            else:
                unaffected_versions.append(package_version)
        except Exception:
            logger.error(
                f"Invalid version range constraints {affected_version_range.constraints!r}"
            )
            continue
    return affected_versions, unaffected_versions


def fetch_response(url):
    """
    Fetch and return `response` from the `url`
    """
    response = requests.get(url)
    if response.status_code == HTTPStatus.OK:
        return response
    raise Exception(f"Failed to fetch data from {url!r} with status code: {response.status_code!r}")


# This should be a method on PackageURL
def plain_purl(purl):
    """
    Return a PackageURL without qualifiers and subpath
    given a purl string or PackageURL object
    """
    if not isinstance(purl, PackageURL):
        purl = PackageURL.from_string(purl)
    return PackageURL(
        type=purl.type,
        namespace=purl.namespace,
        name=purl.name,
        version=purl.version,
    )


def fetch_and_read_from_csv(url):
    response = urllib.request.urlopen(url)
    lines = [l.decode("utf-8") for l in response.readlines()]
    return csv.reader(lines)


def get_cwe_id(cwe_string: str) -> int:
    """
    Split the CWE string and extract the id
    >>> get_cwe_id("CWE-20")
    20
    """
    cwe_id = cwe_string.split("-")[1]
    return int(cwe_id)


def create_weaknesses_list(cwe_strings: str):
    """
    Convert the CWE string to CWE ids and store them to weaknesses list.
    >>> create_weaknesses_list(["CWE-125","CWE-379"])
    [125, 379]
    """
    weaknesses = []
    db = Database()
    for cwe_string in cwe_strings:
        if not cwe_string:
            continue
        cwe_id = get_cwe_id(cwe_string)
        if not cwe_id:
            logger.error("Invalid CWE id: No CWE ID found")
            continue
        try:
            db.get(cwe_id)
            weaknesses.append(cwe_id)
        except InvalidCWEError as e:
            logger.error(f"Error: {e}")
    return weaknesses


def clean_nginx_git_tag(tag):
    """
    Return a cleaned ``version`` string from an nginx git tag.

    Nginx tags git release as in `release-1.2.3`
    This removes the the `release-` prefix.

    For example:
    >>> clean_nginx_git_tag("release-1.2.3") == "1.2.3"
    True
    >>> clean_nginx_git_tag("1.2.3") == "1.2.3"
    True
    """
    if tag.startswith("release-"):
        _, _, tag = tag.partition("release-")
    return tag


def is_vulnerable_nginx_version(version, affected_version_range, fixed_versions):
    """
    Return True if the ``version`` Version for nginx is vulnerable according to
    the nginx approach.

    A ``version`` is vulnerable as explained by @mdounin
    in https://marc.info/?l=nginx&m=164070162912710&w=2 :

        "Note that it is generally trivial to find out if a version is
        vulnerable or not from the information about a vulnerability,
        without any knowledge about nginx branches.  That is:

        - Check if the version is in "Vulnerable" range.  If it's not, the
          version is not vulnerable.

        - If it is, check if the branch is explicitly listed in the "Not
          vulnerable".  If it's not, the version is vulnerable.  If it
          is, check the minor number: if it's greater or equal to the
          version listed as not vulnerable, the version is not vulnerable,
          else the version is vulnerable."

    """
    if version in NginxVersionRange.from_string(affected_version_range.to_string()):
        for fixed_version in fixed_versions:
            if version.value.minor == fixed_version.value.minor and version >= fixed_version:
                return False
        return True
    return False


def get_severity_range(severity_list):
    """
    >>> get_severity_range({'LOW','7.5','5'})
    '0.1 - 7.5'
    >>> get_severity_range({'LOW','Medium'})
    '0.1 - 6.9'
    >>> get_severity_range({'9.5','critical'})
    '9.0 - 10.0'
    >>> get_severity_range({'9.5','critical','unknown'})
    '9.0 - 10.0'
    >>> get_severity_range({})
    """
    if len(severity_list) < 1:
        return
    score_map = {
        "low": [0.1, 3],
        "moderate": [4.0, 6.9],
        "medium": [4.0, 6.9],
        "high": [7.0, 8.9],
        "important": [7.0, 8.9],
        "critical": [9.0, 10.0],
    }

    score_list = []
    for score in severity_list:
        try:
            score_list.append(float(score))
        except ValueError:
            score_range = score_map.get(score.lower()) or []
            if score_range:
                score_list.extend(score_range)
    if not score_list:
        return
    return f"{min(score_list)} - {max(score_list)}"


def get_importer_name(advisory):
    """
    Return the ``importer_name`` of the ``advisory`` that created
    the ``advisory``
    """
    # Importer name can be empty for importers that are being tested
    importer_name = ""
    from vulnerabilities.importers import IMPORTERS_REGISTRY

    importer = IMPORTERS_REGISTRY.get(advisory.created_by) or ""
    if hasattr(importer, "importer_name"):
        importer_name = importer.importer_name
    return importer_name


def get_advisory_url(file, base_path, url):
    """
    Return the advisory URL constructed by combining the base URL with the relative file path.
    """
    relative_path = str(file.relative_to(base_path)).strip("/")
    advisory_url = urljoin(url, relative_path)
    return advisory_url


def purl_to_dict(purl: Union[PackageURL, str], with_empty: bool = True):
    """
    Return a dict of purl components suitable for use in a queryset.
    We need to have specific empty values for using in querysets because of our peculiar model structure.

    For example::
    >>> purl_to_dict(PackageURL.from_string("pkg:generic/postgres"))
    {'type': 'generic', 'namespace': '', 'name': 'postgres', 'version': '', 'qualifiers': '', 'subpath': ''}
    >>> purl_to_dict(PackageURL.from_string("pkg:generic/postgres/postgres@1.2?foo=bar#baz"))
    {'type': 'generic', 'namespace': 'postgres', 'name': 'postgres', 'version': '1.2', 'qualifiers': 'foo=bar', 'subpath': 'baz'}
    """
    if isinstance(purl, str):
        purl = PackageURL.from_string(purl)

    mapping = purl.to_dict(encode=True, empty="")

    if not with_empty:
        return without_empty_values(mapping)

    return mapping


def normalize_purl(purl: Union[PackageURL, str]):
    """
    Return a normalized purl object from a purl string or purl object.
    """
    if isinstance(purl, PackageURL):
        purl = str(purl)
    return PackageURL.from_string(purl)


def get_purl_version_class(purl):
    RANGE_CLASS_BY_SCHEMES["apk"] = AlpineLinuxVersionRange
    purl_version_class = None
    check_version_class = RANGE_CLASS_BY_SCHEMES.get(purl.type, None)
    if check_version_class:
        purl_version_class = check_version_class.version_class
    return purl_version_class


def normalize_text(text):
    """Normalize text by removing whitespace and converting to lowercase."""
    return "".join(text.split()).lower() if text else ""


def normalize_list(lst):
    """Sort a list to ensure consistent ordering."""
    return sorted(lst) if lst else []


def compute_content_id(advisory_data):
    """
    Compute a unique content_id for an advisory by normalizing its data and hashing it.

    :param advisory_data: An AdvisoryData object
    :return: SHA-256 hash digest as content_id
    """

    # Normalize fields
    from vulnerabilities.importer import AdvisoryData
    from vulnerabilities.models import Advisory

    if isinstance(advisory_data, Advisory):
        normalized_data = {
            "aliases": normalize_list(advisory_data.aliases),
            "summary": normalize_text(advisory_data.summary),
            "affected_packages": [
                pkg for pkg in normalize_list(advisory_data.affected_packages) if pkg
            ],
            "references": [ref for ref in normalize_list(advisory_data.references) if ref],
            "weaknesses": normalize_list(advisory_data.weaknesses),
        }
        normalized_data["url"] = advisory_data.url

    elif isinstance(advisory_data, AdvisoryData):
        if advisory_data.references_v2:
            normalized_data = {
                "aliases": normalize_list(advisory_data.aliases),
                "summary": normalize_text(advisory_data.summary),
                "affected_packages": [
                    pkg.to_dict() for pkg in normalize_list(advisory_data.affected_packages) if pkg
                ],
                "references": [
                    ref.to_dict() for ref in normalize_list(advisory_data.references_v2) if ref
                ],
                "severities": [
                    sev.to_dict() for sev in normalize_list(advisory_data.severities) if sev
                ],
                "weaknesses": normalize_list(advisory_data.weaknesses),
            }
        elif advisory_data.references or advisory_data.references == []:
            normalized_data = {
                "aliases": normalize_list(advisory_data.aliases),
                "summary": normalize_text(advisory_data.summary),
                "affected_packages": [
                    pkg.to_dict() for pkg in normalize_list(advisory_data.affected_packages) if pkg
                ],
                "references": [
                    ref.to_dict() for ref in normalize_list(advisory_data.references) if ref
                ],
                "weaknesses": normalize_list(advisory_data.weaknesses),
            }

        normalized_data["url"] = advisory_data.url

    normalized_json = json.dumps(normalized_data, separators=(",", ":"), sort_keys=True)
    content_id = hashlib.sha256(normalized_json.encode("utf-8")).hexdigest()

    return content_id


def create_registry(pipelines):
    """
    Return a mapping of {pipeline ID: pipeline class} for a list of pipelines.
    """
    from vulnerabilities.pipelines import VulnerableCodePipeline

    registry = {}
    for pipeline in pipelines:
        if issubclass(pipeline, VulnerableCodePipeline):
            key = pipeline.pipeline_id
        else:
            # For everything legacy use qualified_name
            key = pipeline.qualified_name

        if not key:
            raise Exception(f"Pipeline ID can not be empty: {pipeline!r}")

        if key in registry:
            raise Exception(f"Duplicate pipeline found: {key}")

        registry[key] = pipeline

    return registry


def ssvc_calculator(ssvc_data):
    """
    Return the ssvc vector and the decision value
    """
    options = ssvc_data.get("options", [])
    timestamp = ssvc_data.get("timestamp")

    # Extract the options into a dictionary
    options_dict = {k: v.lower() for option in options for k, v in option.items()}

    # We copied the table value from this link.
    # https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%20508c.pdf

    # Determining Mission and Well-Being Impact Value
    mission_well_being_table = {
        # (Mission Prevalence, Public Well-being Impact) : "Mission & Well-being"
        ("minimal", "minimal"): "low",
        ("minimal", "material"): "medium",
        ("minimal", "irreversible"): "high",
        ("support", "minimal"): "medium",
        ("support", "material"): "medium",
        ("support", "irreversible"): "high",
        ("essential", "minimal"): "high",
        ("essential", "material"): "high",
        ("essential", "irreversible"): "high",
    }

    if "Mission Prevalence" not in options_dict:
        options_dict["Mission Prevalence"] = "minimal"

    if "Public Well-being Impact" not in options_dict:
        options_dict["Public Well-being Impact"] = "material"

    options_dict["Mission & Well-being"] = mission_well_being_table[
        (options_dict["Mission Prevalence"], options_dict["Public Well-being Impact"])
    ]

    decision_key = (
        options_dict.get("Exploitation"),
        options_dict.get("Automatable"),
        options_dict.get("Technical Impact"),
        options_dict.get("Mission & Well-being"),
    )

    decision_points = {
        "Exploitation": {"E": {"none": "N", "poc": "P", "active": "A"}},
        "Automatable": {"A": {"no": "N", "yes": "Y"}},
        "Technical Impact": {"T": {"partial": "P", "total": "T"}},
        "Public Well-being Impact": {"B": {"minimal": "M", "material": "A", "irreversible": "I"}},
        "Mission Prevalence": {"P": {"minimal": "M", "support": "S", "essential": "E"}},
        "Mission & Well-being": {"M": {"low": "L", "medium": "M", "high": "H"}},
    }

    # Create the SSVC vector
    ssvc_vector = "SSVCv2/"
    for key, value_map in options_dict.items():
        options_key = decision_points.get(key)
        for lhs, rhs_map in options_key.items():
            ssvc_vector += f"{lhs}:{rhs_map.get(value_map)}/"

    # "Decision": {"D": {"Track": "T", "Track*": "R", "Attend": "A", "Act": "C"}},
    decision_values = {"Track": "T", "Track*": "R", "Attend": "A", "Act": "C"}

    decision_lookup = {
        ("none", "no", "partial", "low"): "Track",
        ("none", "no", "partial", "medium"): "Track",
        ("none", "no", "partial", "high"): "Track",
        ("none", "no", "total", "low"): "Track",
        ("none", "no", "total", "medium"): "Track",
        ("none", "no", "total", "high"): "Track*",
        ("none", "yes", "partial", "low"): "Track",
        ("none", "yes", "partial", "medium"): "Track",
        ("none", "yes", "partial", "high"): "Attend",
        ("none", "yes", "total", "low"): "Track",
        ("none", "yes", "total", "medium"): "Track",
        ("none", "yes", "total", "high"): "Attend",
        ("poc", "no", "partial", "low"): "Track",
        ("poc", "no", "partial", "medium"): "Track",
        ("poc", "no", "partial", "high"): "Track*",
        ("poc", "no", "total", "low"): "Track",
        ("poc", "no", "total", "medium"): "Track*",
        ("poc", "no", "total", "high"): "Attend",
        ("poc", "yes", "partial", "low"): "Track",
        ("poc", "yes", "partial", "medium"): "Track",
        ("poc", "yes", "partial", "high"): "Attend",
        ("poc", "yes", "total", "low"): "Track",
        ("poc", "yes", "total", "medium"): "Track*",
        ("poc", "yes", "total", "high"): "Attend",
        ("active", "no", "partial", "low"): "Track",
        ("active", "no", "partial", "medium"): "Track",
        ("active", "no", "partial", "high"): "Attend",
        ("active", "no", "total", "low"): "Track",
        ("active", "no", "total", "medium"): "Attend",
        ("active", "no", "total", "high"): "Act",
        ("active", "yes", "partial", "low"): "Attend",
        ("active", "yes", "partial", "medium"): "Attend",
        ("active", "yes", "partial", "high"): "Act",
        ("active", "yes", "total", "low"): "Attend",
        ("active", "yes", "total", "medium"): "Act",
        ("active", "yes", "total", "high"): "Act",
    }

    decision = decision_lookup.get(decision_key, "")

    if decision:
        ssvc_vector += f"D:{decision_values.get(decision)}/"

    if timestamp:
        timestamp_formatted = dateparser.parse(timestamp).strftime("%Y-%m-%dT%H:%M:%SZ")

        ssvc_vector += f"{timestamp_formatted}/"
    return ssvc_vector, decision


def compute_patch_checksum(patch_text: str):
    """
    Compute SHA-512 checksum for patch text.
    """
    return hashlib.sha512(patch_text.encode("utf-8")).hexdigest()
