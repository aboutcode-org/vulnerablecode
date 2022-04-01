import dataclasses
import logging
import traceback
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List
from typing import MutableMapping
from typing import Optional
from typing import Set
from urllib.parse import urlparse

import requests
from dateutil import parser as dateparser
from django.utils.dateparse import parse_datetime

from vulnerabilities.helpers import get_item
from vulnerabilities.package_managers import VersionResponse

LOGGER = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class LegacyVersion:
    value: str
    release_date: Optional[datetime] = None


@dataclasses.dataclass
class VersionResponse:
    valid_versions: Set[str] = dataclasses.field(default_factory=set)
    newer_versions: Set[str] = dataclasses.field(default_factory=set)


def get_response(url, type="json"):
    try:
        resp = requests.get(url=url)
    except:
        LOGGER.error(traceback.format_exc())
        return None
    if not resp.status_code == 200:
        LOGGER.error(f"Error while fetching {url}: {resp.status_code}")
        return None
    if type == "read":
        return resp.content
    if type == "text":
        return resp.text
    return resp.json()


class VersionAPI:
    def __init__(self, cache: MutableMapping[str, Set[LegacyVersion]] = None):
        self.cache = cache or {}

    def get(self, package_name, until=None) -> VersionResponse:
        new_versions = set()
        valid_versions = set()
        for version in self.cache.get(package_name, set()):
            if until and version.release_date and version.release_date > until:
                new_versions.add(version.value)
            else:
                valid_versions.add(version.value)

        return VersionResponse(valid_versions=valid_versions, newer_versions=new_versions)

    def load_api(self, pkg_set):
        """
        Populate the cache with the versions of the packages in pkg_set
        """
        for pkg in pkg_set:
            if pkg in self.cache:
                continue
            self.fetch(pkg)

    def fetch(self, pkg):
        """
        Override this method to fetch the pkg's version in the cache
        """
        raise NotImplementedError


class PypiVersionAPI(VersionAPI):

    package_type = "pypi"

    def fetch(self, pkg):
        url = f"https://pypi.org/pypi/{pkg}/json"
        versions = set()
        response = get_response(url=url)

        if not response:
            self.cache[pkg] = versions
            return

        releases = response.get("releases") or {}
        for version, download_items in releases.items():
            if download_items:
                latest_download_item = max(
                    download_items,
                    key=lambda download_item: dateparser.parse(
                        download_item["upload_time_iso_8601"]
                    )
                    if download_item.get("upload_time_iso_8601")
                    else None,
                )
                versions.add(
                    LegacyVersion(
                        value=version,
                        release_date=dateparser.parse(latest_download_item["upload_time_iso_8601"])
                        if latest_download_item.get("upload_time_iso_8601")
                        else None,
                    )
                )
        self.cache[pkg] = versions


class RubyVersionAPI(VersionAPI):

    package_type = "gem"

    def fetch(self, pkg):
        url = f"https://rubygems.org/api/v1/versions/{pkg}.json"
        versions = set()
        response = get_response(url=url)
        if not response:
            self.cache[pkg] = versions
            return
        for release in response:
            if release.get("published_at"):
                release_date = dateparser.parse(release["published_at"])
            elif release.get("created_at"):
                release_date = dateparser.parse(release["created_at"])
            else:
                release_date = None
            if release.get("number"):
                versions.add(LegacyVersion(value=release["number"], release_date=release_date))
            else:
                LOGGER.error(f"Failed to parse release {release}")

        self.cache[pkg] = versions


class MavenVersionAPI(VersionAPI):

    package_type = "maven"

    def fetch(self, pkg) -> None:
        artifact_comps = pkg.split(":")
        endpoint = self.artifact_url(artifact_comps)

        resp = get_response(url=endpoint, type="read")

        if not resp:
            self.cache[pkg] = set()
            return

        xml_resp = ET.ElementTree(ET.fromstring(resp.decode("utf-8")))
        self.cache[pkg] = self.extract_versions(xml_resp)

    @staticmethod
    def artifact_url(artifact_comps: List[str]) -> str:
        base_url = "https://repo1.maven.org/maven2/{}"
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
        suffix = group_url + "/" + artifact_id + "/" + "maven-metadata.xml"
        endpoint = base_url.format(suffix)

        return endpoint

    @staticmethod
    def extract_versions(xml_response: ET.ElementTree) -> Set[LegacyVersion]:
        all_versions = set()
        for child in xml_response.getroot().iter():
            if child.tag == "version" and child.text:
                all_versions.add(LegacyVersion(child.text))

        return all_versions


class NugetVersionAPI(VersionAPI):

    package_type = "nuget"

    def fetch(self, pkg) -> None:
        endpoint = self.nuget_url(pkg)
        resp = get_response(url=endpoint)
        if not resp:
            self.cache[pkg] = set()
            return
        self.cache[pkg] = self.extract_versions(resp)

    @staticmethod
    def nuget_url(pkg_name: str) -> str:
        pkg_name = pkg_name.lower().strip()
        base_url = f"https://api.nuget.org/v3/registration5-semver1/{pkg_name}/index.json"
        return base_url

    @staticmethod
    def extract_versions(resp: dict) -> Set[LegacyVersion]:
        all_versions = set()
        for entry_group in resp.get("items") or []:
            for entry in entry_group.get("items") or []:
                catalog_entry = entry.get("catalogEntry") or {}
                version = catalog_entry.get("version")
                release_date = (
                    dateparser.parse(catalog_entry["published"])
                    if catalog_entry.get("published")
                    else None
                )
                if version:
                    all_versions.add(
                        LegacyVersion(
                            value=version,
                            release_date=release_date,
                        )
                    )

        return all_versions


class GoproxyVersionAPI(VersionAPI):

    package_type = "golang"

    def __init__(self, cache: MutableMapping[str, Set[LegacyVersion]] = None):
        super().__init__(cache)
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
            LOGGER.error(f"Not a valid Go URL path {url_path} trim_go_url_path")
            return None
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
    def parse_version_info(version_info: str, escaped_pkg: str) -> Optional[LegacyVersion]:
        v = version_info.split()
        if not v:
            return None
        value = v[0]
        if len(v) > 1:
            # get release date from the second part. see https://github.com/golang/go/blob/master/src/cmd/go/internal/modfetch/proxy.go#latest()
            release_date = parse_datetime(v[1])
        else:
            escaped_ver = GoproxyVersionAPI.escape_path(value)
            resp_json = get_response(
                url=f"https://proxy.golang.org/{escaped_pkg}/@v/{escaped_ver}.info"
            )
            if not resp_json:
                traceback.print_exc()
                print(
                    f"error while fetching version info for {escaped_pkg}/{escaped_ver} from goproxy"
                )
            release_date = parse_datetime(resp_json.get("Time", "")) if resp_json else None

        return LegacyVersion(value=value, release_date=release_date)

    def fetch(self, pkg: str):
        # escape uppercase in module path
        escaped_pkg = GoproxyVersionAPI.escape_path(pkg)
        trimmed_pkg = pkg
        resp_text = None
        # resolve module name from package name, see https://go.dev/ref/mod#resolve-pkg-mod
        while escaped_pkg is not None:
            url = f"https://proxy.golang.org/{escaped_pkg}/@v/list"
            resp_text = get_response(url=url, type="text")
            if not resp_text:
                escaped_pkg = GoproxyVersionAPI.trim_go_url_path(escaped_pkg)
                trimmed_pkg = GoproxyVersionAPI.trim_go_url_path(trimmed_pkg) or ""
                continue
            break
        if resp_text is None or escaped_pkg is None or trimmed_pkg is None:
            print(f"error while fetching versions for {pkg} from goproxy")
            return
        self.module_name_by_package_name[pkg] = trimmed_pkg
        versions = set()
        for version_info in resp_text.split("\n"):
            version = GoproxyVersionAPI.parse_version_info(version_info, escaped_pkg)
            if version is not None:
                versions.add(version)
        self.cache[pkg] = versions


class ComposerVersionAPI(VersionAPI):

    package_type = "composer"

    def fetch(self, pkg) -> None:
        endpoint = self.composer_url(pkg)
        if endpoint:
            resp = get_response(url=endpoint)
            if not resp:
                self.cache[pkg] = set()
                return
            self.cache[pkg] = self.extract_versions(resp, pkg)

    @staticmethod
    def composer_url(pkg_name: str) -> Optional[str]:
        try:
            vendor, name = pkg_name.split("/")
        except ValueError:
            # TODO Log this
            return
        return f"https://repo.packagist.org/p/{vendor}/{name}.json"

    @staticmethod
    def extract_versions(resp: dict, pkg_name: str) -> Set[LegacyVersion]:
        all_versions = set()
        for version in get_item(resp, "packages", pkg_name) or []:
            if "dev" in version:
                continue

            # This if statement ensures, that all_versions contains only released versions
            # See https://github.com/composer/composer/blob/44a4429978d1b3c6223277b875762b2930e83e8c/doc/articles/versions.md#tags  # nopep8
            # for explanation of removing 'v'
            time = get_item(resp, "packages", pkg_name, version, "time")
            all_versions.add(
                LegacyVersion(
                    value=version.lstrip("v"),
                    release_date=dateparser.parse(time) if time else None,
                )
            )
        return all_versions
