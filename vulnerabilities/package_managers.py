#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import dataclasses
import json
import logging
import traceback
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Iterable
from typing import List
from typing import Optional
from typing import Set
from urllib.parse import urlparse

import requests
from dateutil import parser as dateparser
from django.utils.dateparse import parse_datetime
from packageurl import PackageURL

from vulnerabilities import utils
from vulnerabilities.utils import get_item

logger = logging.getLogger(__name__)

"""
Utilities to retrieve lists of package versions from remote package
repositories, registries or APIs.
"""

# FIXME: use purl for cache key, rather than an undefined package_name key
# FIXME: DO NOT cache by default as this is an optimization that does not work for long running processes
# FIXME: DO NOT use set() for storing version lists: they lose the original ordering


@dataclasses.dataclass(frozen=True)
class PackageVersion:
    value: str
    release_date: Optional[datetime] = None

    def to_dict(self):
        release_date = self.release_date
        release_date = release_date and release_date.isoformat()
        return dict(value=self.value, release_date=release_date)


@dataclasses.dataclass
class VersionResponse:
    valid_versions: Set[str] = dataclasses.field(default_factory=set)
    newer_versions: Set[str] = dataclasses.field(default_factory=set)


def get_response(url, content_type="json", headers=None):
    """
    Fetch ``url`` and return its content as ``content_type`` which is one of
    binary, text or json.
    """
    assert content_type in ("binary", "text", "json")

    try:
        resp = requests.get(url=url, headers=headers)
    except:
        logger.error(traceback.format_exc())
        return
    if not resp.status_code == 200:
        logger.error(f"Error while fetching {url!r}: {resp.status_code!r}")
        return

    if content_type == "binary":
        return resp.content
    elif content_type == "text":
        return resp.text
    elif content_type == "json":
        return resp.json()


class VersionAPI:
    """
    Base class for version APIs classes that fetch package versions from remote
    package repositories, registries or APIs.
    """

    # subclasses must define the purl package_type they catter to
    package_type = None

    def get_until(self, package_name, until=None) -> VersionResponse:
        """
        Return a VersionResponse given a ``package_name`` cache key and an
        optional ``until`` datetime object for a date "until" which to fetch
        versions.
        """
        new_versions = set()
        valid_versions = set()

        for version in self.fetch(package_name):
            if until and version.release_date and version.release_date > until:
                new_versions.add(version.value)
            else:
                valid_versions.add(version.value)

        return VersionResponse(valid_versions=valid_versions, newer_versions=new_versions)

    def fetch(self, pkg: str) -> Iterable[PackageVersion]:
        """
        Yield PackageVersion versions given a ``pkg`` package name.
        Subclasses must override this method and can create caches as needed.
        """
        raise NotImplementedError


def remove_debian_default_epoch(version):
    """
    Remove the default epoch from a Debian ``version`` string.
    """
    return version and version.replace("0:", "")


class LaunchpadVersionAPI(VersionAPI):
    """
    Fetch versions of Ubuntu debian packages from Launchpad
    """

    package_type = "deb"

    def fetch(self, pkg: str) -> Iterable[PackageVersion]:
        url = (
            f"https://api.launchpad.net/1.0/ubuntu/+archive/primary?"
            "ws.op=getPublishedSources&source_name={pkg}&exact_match=true"
        )

        while True:
            response = get_response(url=url, content_type="json")

            entries = response["entries"]
            if not entries:
                break

            for release in entries:
                source_package_version = release["source_package_version"]
                source_package_version = remove_debian_default_epoch(source_package_version)
                yield PackageVersion(
                    value=source_package_version,
                    release_date=release["date_published"],
                )
            if response.get("next_collection_link"):
                url = response["next_collection_link"]
            else:
                break


class PypiVersionAPI(VersionAPI):
    """
    Fetch versions of Python pypi packages from the PyPI API.
    """

    package_type = "pypi"

    def fetch(self, pkg):
        response = get_response(url=f"https://pypi.org/pypi/{pkg}/json")
        if not response:
            # FIXME: raise!
            return

        releases = response.get("releases") or {}
        for version, download_items in releases.items():
            if not download_items:
                continue

            release_date = self.get_latest_date(download_items)
            yield PackageVersion(
                value=version,
                release_date=release_date,
            )

    def get_latest_date(self, downloads):
        """
        Return the latest date from a list of mapping of PyPI ``downloadss`` or  None.

        The data has this shape:
        [
          {
            ....
            "upload_time_iso_8601": "2010-12-23T05:14:23.509436Z",
            "url": "https://files.pythonhosted.org/packages/8f/1f/c20ca80fa5df025cc/Django-1.1.3.tar.gz",
          },
          {
            ....
            "upload_time_iso_8601": "2010-12-23T05:20:23.509436Z",
            "url": "https://files.pythonhosted.org/packages/8f/1f/561bddc20ca80fa5df025cc/Django-1.1.3.wheel",
          },
        ]
        """
        latest_date = None
        for download in downloads:
            upload_time = download.get("upload_time_iso_8601")
            if upload_time:
                current_date = dateparser.parse(upload_time)
            if not latest_date:
                latest_date = current_date
            else:
                if current_date > latest_date:
                    latest_date = current_date
        return latest_date


class CratesVersionAPI(VersionAPI):
    """
    Fetch versions of Rust cargo packages from the crates.io API.
    """

    package_type = "cargo"

    def fetch(self, pkg):
        url = f"https://crates.io/api/v1/crates/{pkg}"
        response = get_response(url=url, content_type="json")
        for version_info in response["versions"]:
            yield PackageVersion(
                value=version_info["num"],
                release_date=dateparser.parse(version_info["updated_at"]),
            )


class RubyVersionAPI(VersionAPI):
    """
    Fetch versions of Rubygems packages from the rubygems API.
    """

    package_type = "gem"

    def fetch(self, pkg):
        url = f"https://rubygems.org/api/v1/versions/{pkg}.json"
        response = get_response(url=url, content_type="json")
        if not response:
            return
        for release in response:
            if release.get("published_at"):
                release_date = dateparser.parse(release["published_at"])
            elif release.get("created_at"):
                release_date = dateparser.parse(release["created_at"])
            else:
                release_date = None
            if release.get("number"):
                yield PackageVersion(value=release["number"], release_date=release_date)
            else:
                logger.error(f"Failed to parse release {release} from url: {url}")


class NpmVersionAPI(VersionAPI):
    """
    Fetch versions of npm packages from the npm registry API.
    """

    package_type = "npm"

    def fetch(self, pkg):
        url = f"https://registry.npmjs.org/{pkg}"
        response = get_response(url=url, content_type="json")
        if not response:
            logger.error(f"Failed to fetch {url}")
            return
        for version in response.get("versions") or []:
            release_date = response.get("time", {}).get(version)
            release_date = release_date and dateparser.parse(release_date) or None
            yield PackageVersion(value=version, release_date=release_date)


class DebianVersionAPI(VersionAPI):
    """
    Fetch versions of Debian debian packages from the sources.debian.org API
    """

    package_type = "deb"

    def fetch(self, pkg):
        # Need to set the headers, because the Debian API upgrades
        # the connection to HTTP 2.0
        response = get_response(
            url=f"https://sources.debian.org/api/src/{pkg}",
            headers={"Connection": "keep-alive"},
            content_type="json",
        )
        if response and (response.get("error") or not response.get("versions")):
            return

        for release in response["versions"]:
            version = release["version"]
            version = remove_debian_default_epoch(version)
            yield PackageVersion(value=version)


class MavenVersionAPI(VersionAPI):
    """
    Fetch versions of Maven packages from Maven Central maven-metadata.xml data
    """

    package_type = "maven"

    def fetch(self, pkg: str) -> Iterable[PackageVersion]:
        artifact_comps = pkg.split(":")
        endpoint = self.artifact_url(artifact_comps)
        response = get_response(url=endpoint, content_type="binary")
        if response:
            xml_resp = ET.ElementTree(ET.fromstring(response.decode("utf-8")))
            yield from self.extract_versions(xml_resp)

    @staticmethod
    def artifact_url(artifact_comps: List[str]) -> str:
        try:
            group_id, artifact_id = artifact_comps
        except ValueError:
            if len(artifact_comps) == 1:
                group_id = artifact_comps[0]
                artifact_id = artifact_comps[0].split(".")[-1]

            elif len(artifact_comps) == 3:
                group_id, artifact_id = list(dict.fromkeys(artifact_comps))

            else:
                raise

        group_url = group_id.replace(".", "/")
        endpoint = f"https://repo1.maven.org/maven2/{group_url}/{artifact_id}/maven-metadata.xml"
        return endpoint

    @staticmethod
    def extract_versions(xml_response: ET.ElementTree) -> Iterable[PackageVersion]:
        for child in xml_response.getroot().iter():
            if child.tag == "version" and child.text:
                yield PackageVersion(value=child.text)


class NugetVersionAPI(VersionAPI):
    """
    Fetch versions of NuGet packages from the nuget.org API
    """

    package_type = "nuget"

    def fetch(self, pkg: str) -> Iterable[PackageVersion]:
        pkg = pkg.lower().strip()
        url = f"https://api.nuget.org/v3/registration5-semver1/{pkg}/index.json"
        resp = get_response(url=url)
        if resp:
            yield from self.extract_versions(resp)

    @staticmethod
    def extract_versions(response: dict) -> Iterable[PackageVersion]:
        for entry_group in response.get("items") or []:
            for entry in entry_group.get("items") or []:
                catalog_entry = entry.get("catalogEntry") or {}
                version = catalog_entry.get("version")
                if not version:
                    continue
                release_date = catalog_entry.get("published")
                if release_date:
                    release_date = dateparser.parse(release_date)
                yield PackageVersion(
                    value=version,
                    release_date=release_date,
                )


def cleaned_version(version):
    """
    Return a ``version`` string stripped from leading "v" prefix.
    """
    return version.lstrip("vV")


class ComposerVersionAPI(VersionAPI):
    """
    Fetch versions of PHP Composer packages from the packagist.org API
    """

    package_type = "composer"

    def fetch(self, pkg: str) -> Iterable[PackageVersion]:
        response = get_response(url=f"https://repo.packagist.org/p/{pkg}.json")
        if response:
            yield from self.extract_versions(response, pkg)

    @staticmethod
    def extract_versions(resp: dict, pkg: str) -> Iterable[PackageVersion]:
        for version in get_item(resp, "packages", pkg) or []:
            if "dev" in version:
                continue

            # This if statement ensures, that all_versions contains only released versions
            # See https://github.com/composer/composer/blob/44a4429978d1b3c6223277b875762b2930e83e8c/doc/articles/versions.md#tags  # nopep8
            # for explanation of removing 'v'
            time = get_item(resp, "packages", pkg, version, "time")
            yield PackageVersion(
                value=cleaned_version(version),
                release_date=dateparser.parse(time) if time else None,
            )


class GraphQLError(Exception):
    pass


# Isolated network call for simplicity of testing
def get_gh_response(endpoint: str, headers: dict, query: dict):
    return requests.post(endpoint, headers=headers, json=query).json()


# FIXME: this code is duplicated with the imports/github.py code


class GitHubTagsAPI(VersionAPI):
    """
    Fetch tags of Git repositories from the GitHub graphql API
    This requires the "GH_TOKEN" environment variable to be set.
    """

    package_type = "github"

    GQL_QUERY = """
    query getTags($name: String!, $owner: String!, $after: String)
    {
        repository(name: $name, owner: $owner) {
            refs(refPrefix: "refs/tags/", first: 100, after: $after) {
                totalCount
                pageInfo {
                    endCursor
                    hasNextPage
                }
                nodes {
                    name
                    target {
                        ... on Commit {
                            committedDate
                        }
                        ... on Tag {
                                target {
                                ... on Commit {
                                    committedDate
                                }
                            }
                        }
                    }
                }
            }
        }
    }"""

    def fetch(self, pkg: str) -> Iterable[PackageVersion]:
        """
        Yield PackageVersion from the Git tags of the ``pkg`` "{owner}/{repo}"
        repository using the GitHub API.
        ``pkg`` is a string of format "{repo_owner}/{repo_name}" Example value
        of owner_repo = "nexB/scancode-toolkit"
        """

        for node in self.fetch_tag_nodes(pkg):
            name = node["name"]
            target = node["target"]

            # in case the tag is a signed tag, then the commit info is in target['target']
            if "committedDate" not in target:
                target = target["target"]

            committed_date = target.get("committedDate")
            if committed_date:
                release_date = dateparser.parse(committed_date)
            else:
                # Tags can actually point to tree and not commit, so
                # there is no guaranteed date. This is seen in the linux kernel.
                # Github cannot even properly display it.
                # https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/refs/tags/v2.6.11
                release_date = None

            yield PackageVersion(value=name, release_date=release_date)

    def fetch_tag_nodes(self, pkg: str, _DUMP_TO_FILE=False) -> Iterable[PackageVersion]:
        """
        Yield node "name/target} mappings for Git tags of the ``pkg`` "{owner}/{repo}"
        GitHub repository using the GitHub graphql API. ``pkg`` is a string of
        format "{repo_owner}/{repo_name}" as in "nexB /scancode-toolkit"

        Each node has this shape:
          {
            "name": "v2.6.24-rc5",
            "target": {
              "target": {
                "committedDate": "2007-12-11T03:48:43Z"
              }
            }
          },
        """
        repo_owner, repo_name = pkg.split("/")

        variables = {
            "owner": repo_owner,
            "name": repo_name,
        }
        graphql_query = {
            "query": self.GQL_QUERY,
            "variables": variables,
        }

        idx = 0
        while True:
            response = utils.fetch_github_graphql_query(graphql_query)

            # this is a convenience for testing to dump results to a file
            if _DUMP_TO_FILE:
                fn = f"github-{repo_owner}-{repo_name}-{idx}.json"
                print(f"fetch_tag_nodes: Dumping to file: {fn}")
                with open(fn, "w") as o:
                    json.dump(response, o, indent=2)
                idx += 1

            refs = response["data"]["repository"]["refs"]
            for node in refs["nodes"]:
                yield node

            page_info = refs["pageInfo"]
            if not page_info["hasNextPage"]:
                break

            # to fetch next page, we just set the after variable to endCursor
            variables["after"] = page_info["endCursor"]


class HexVersionAPI(VersionAPI):
    """
    Fetch versions of Erlang packages from the hex API
    """

    package_type = "hex"

    def fetch(self, pkg: str) -> Iterable[PackageVersion]:
        response = get_response(
            url=f"https://hex.pm/api/packages/{pkg}",
            content_type="json",
        )
        for release in response["releases"]:
            yield PackageVersion(
                value=release["version"],
                release_date=dateparser.parse(release["inserted_at"]),
            )


class GoproxyVersionAPI(VersionAPI):
    """
    Fetch versions of Go "golang" packages from the Go proxy API
    """

    package_type = "golang"

    def __init__(self):
        self.module_name_by_package_name = {}

    @staticmethod
    def trim_go_url_path(url_path: str) -> Optional[str]:
        """
        Return a trimmed Go `url_path` removing trailing
        package references and keeping only the module
        references.

        Github advisories for Go are using package names
        such as "https://github.com/nats-io/nats-server/v2/server"
        (e.g., https://github.com/advisories/GHSA-jp4j-47f9-2vc3 ),
        yet goproxy works with module names instead such as
        "https://github.com/nats-io/nats-server" (see for details
        https://golang.org/ref/mod#goproxy-protocol ).
        This functions trims the trailing part(s) of a package URL
        and returns the remaining the module name.
        For example:
        >>> module = "github.com/xx/a"
        >>> assert GoproxyVersionAPI.trim_go_url_path("https://github.com/xx/a/b") == module
        """
        # some advisories contains this prefix in package name, e.g. https://github.com/advisories/GHSA-7h6j-2268-fhcm
        if url_path.startswith("https://pkg.go.dev/"):
            url_path = url_path[len("https://pkg.go.dev/") :]
        parsed_url_path = urlparse(url_path)
        path = parsed_url_path.path
        parts = path.split("/")
        if len(parts) < 3:
            logger.error(f"Not a valid Go URL path {url_path} trim_go_url_path")
            return
        else:
            joined_path = "/".join(parts[:3])
            return f"{parsed_url_path.netloc}{joined_path}"

    @staticmethod
    def escape_path(path: str) -> str:
        """
        Return an case-encoded module path or version name.

        This is done by replacing every uppercase letter with an exclamation
        mark followed by the corresponding lower-case letter, in order to
        avoid ambiguity when serving from case-insensitive file systems.
        Refer to https://golang.org/ref/mod#goproxy-protocol.
        """
        escaped_path = ""
        for c in path:
            if c >= "A" and c <= "Z":
                # replace uppercase with !lowercase
                escaped_path += "!" + chr(ord(c) + ord("a") - ord("A"))
            else:
                escaped_path += c
        return escaped_path

    @staticmethod
    def fetch_version_info(version_info: str, escaped_pkg: str) -> Optional[PackageVersion]:
        v = version_info.split()
        if not v:
            return None

        value = v[0]
        if len(v) > 1:
            # get release date from the second part. see
            # https://github.com/golang/go/blob/master/src/cmd/go/internal/modfetch/proxy.go#latest()
            release_date = parse_datetime(v[1])
        else:
            escaped_ver = GoproxyVersionAPI.escape_path(value)
            response = get_response(
                url=f"https://proxy.golang.org/{escaped_pkg}/@v/{escaped_ver}.info",
                content_type="json",
            )

            if not response:
                logger.error(
                    f"Error while fetching version info for {escaped_pkg}/{escaped_ver} "
                    f"from goproxy:\n{traceback.format_exc()}"
                )
            release_date = parse_datetime(response.get("Time", "")) if response else None

        return PackageVersion(value=value, release_date=release_date)

    def fetch(self, pkg: str) -> Iterable[PackageVersion]:

        # escape uppercase in module path
        escaped_pkg = self.escape_path(pkg)
        trimmed_pkg = pkg
        response = None
        # resolve module name from package name, see https://go.dev/ref/mod#resolve-pkg-mod
        while escaped_pkg is not None:
            url = f"https://proxy.golang.org/{escaped_pkg}/@v/list"
            response = get_response(url=url, content_type="text")
            if not response:
                trimmed_escaped_pkg = self.trim_go_url_path(escaped_pkg)
                trimmed_pkg = self.trim_go_url_path(trimmed_pkg) or ""
                if trimmed_escaped_pkg == escaped_pkg:
                    break

                escaped_pkg = trimmed_escaped_pkg
                continue

            break

        if response is None or escaped_pkg is None or trimmed_pkg is None:
            logger.error(f"Error while fetching versions for {pkg!r} from goproxy")
            return
        self.module_name_by_package_name[pkg] = trimmed_pkg
        for version_info in response.split("\n"):
            version = self.fetch_version_info(version_info, escaped_pkg)
            if version:
                yield version


VERSION_API_CLASSES = {
    MavenVersionAPI,
    NugetVersionAPI,
    ComposerVersionAPI,
    PypiVersionAPI,
    RubyVersionAPI,
    GoproxyVersionAPI,
    NpmVersionAPI,
    HexVersionAPI,
    LaunchpadVersionAPI,
    CratesVersionAPI,
    DebianVersionAPI,
    GitHubTagsAPI,
}

VERSION_API_CLASSES_BY_PACKAGE_TYPE = {cls.package_type: cls for cls in VERSION_API_CLASSES}


def get_api_package_name(purl: PackageURL) -> str:
    """
    Return the package name expected by the GitHub API given a PackageURL
    >>> get_api_package_name(PackageURL(type="maven", namespace="org.apache.commons", name="commons-lang3"))
    'org.apache.commons:commons-lang3'
    >>> get_api_package_name(PackageURL(type="composer", namespace="foo", name="bar"))
    'foo/bar'
    """
    if not purl.name:
        return None
    if purl.type in ("nuget", "pypi", "gem", "deb") or not purl.namespace:
        return purl.name
    if purl.type == "maven":
        return f"{purl.namespace}:{purl.name}"
    if purl.type in ("composer", "golang", "npm"):
        return f"{purl.namespace}/{purl.name}"

    logger.error(f"get_api_package_name: Unknown PURL {purl!r}")
