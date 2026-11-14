#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

"""
Helpers to list published package versions for version-range unfurl.

Most ecosystems go through fetchcode. Go is handled here because fetchcode's
goproxy client is too strict for unfurl:

1. fetchcode GETs ``/@v/{version}.info`` for every version in ``/@v/list``.
   Some listed versions 404 on ``.info`` (retracted or never fully published).
   fetchcode then raises and we lose the rest of the list.

   Example: ``pkg:golang/github.com/traefik/traefik/v3`` lists
   ``v3.0.0-beta1``, but
   ``https://proxy.golang.org/github.com/traefik/traefik/v3/@v/v3.0.0-beta1.info``
   is 404. ``v3.0.0.info`` is fine. Unfurl only needs the version strings from
   ``/@v/list``.

2. fetchcode trims Go paths to three segments, which drops major-version
   suffixes such as ``/v3`` and nested modules such as
   ``github.com/mattermost/mattermost/server/v8``.

3. The Go vulnerability database uses ``stdlib``, ``cmd/go``, ``runtime``,
   and similar names. Those are not proxy modules (first path element has no
   dot). Their versions are Go releases from ``https://go.dev/dl/``.

4. Vanity modules can be a single path segment with a dot, for example
   ``gitea.dev`` or ``tailscale.com``. Those are valid goproxy module paths.
"""

import logging
from traceback import format_exc as traceback_format_exc
from typing import Callable
from typing import Optional
from typing import Set
from typing import Union

import requests
from fetchcode.package_versions import SUPPORTED_ECOSYSTEMS as FETCHCODE_SUPPORTED_ECOSYSTEMS
from fetchcode.package_versions import versions
from packageurl import PackageURL

GOPROXY_URL = "https://proxy.golang.org"
GO_RELEASES_URL = "https://go.dev/dl/?mode=json&include=all"
# Hosting sites that are never themselves Go modules.
GO_VCS_ROOTS = {"github.com", "gitlab.com", "bitbucket.org", "gopkg.in"}

_GO_RELEASE_VERSIONS = None


def get_versions(purl: Union[PackageURL, str], logger: Callable = None):
    """
    Return a set of known version strings for ``purl``, or None if the
    ecosystem is not supported.

    Non-Go packages use fetchcode. Go packages use ``get_golang_versions``.
    A leading ``v`` / ``V`` is stripped so versions match univers ranges.

    For example a Traefik PURL yields values such as ``{"3.0.0", "3.1.0"}``
    rather than ``{"v3.0.0", "v3.1.0"}``.
    """
    if isinstance(purl, str):
        purl = PackageURL.from_string(purl)

    if purl.type not in FETCHCODE_SUPPORTED_ECOSYSTEMS:
        return

    if purl.type == "golang":
        return get_golang_versions(purl, logger)

    try:
        return {v.value.lstrip("vV") for v in versions(str(purl))}
    except Exception as e:
        if logger:
            logger(
                f"Error while fetching known versions for {purl!s}: {e!r} \n {traceback_format_exc()}",
                level=logging.ERROR,
            )


def golang_module_from_purl(purl: PackageURL) -> str:
    """
    Return the Go module path encoded in a golang PackageURL.

    PackageURL splits ``pkg:golang/github.com/traefik/traefik/v3`` into
    namespace ``github.com/traefik/traefik`` and name ``v3``. The proxy
    speaks in a single module path, so those parts are joined again::

        >>> from packageurl import PackageURL
        >>> golang_module_from_purl(PackageURL.from_string(
        ...     "pkg:golang/github.com/traefik/traefik/v3"))
        'github.com/traefik/traefik/v3'
        >>> golang_module_from_purl(PackageURL.from_string("pkg:golang/stdlib"))
        'stdlib'
        >>> golang_module_from_purl(PackageURL.from_string("pkg:golang/gitea.dev"))
        'gitea.dev'
    """
    return "/".join(part for part in (purl.namespace, purl.name) if part)


def is_go_standard_library_module(module: str) -> bool:
    """
    Return True if ``module`` is the Go standard library (or a std package).

    Go module paths must have a dot in the first element (``github.com/...``,
    ``gitea.dev``). Names without that dot are stdlib in vulndb data:
    ``stdlib``, ``std``, ``cmd``, ``cmd/go``, ``runtime``, ``net``.

    Those are not on proxy.golang.org (``malformed module path: missing dot
    in first path element``). Their versions are Go toolchain releases.

        >>> is_go_standard_library_module("stdlib")
        True
        >>> is_go_standard_library_module("cmd/go")
        True
        >>> is_go_standard_library_module("runtime")
        True
        >>> is_go_standard_library_module("github.com/traefik/traefik/v3")
        False
        >>> is_go_standard_library_module("gitea.dev")
        False
    """
    first = (module.split("/")[0] or "").lower()
    if first in {"std", "stdlib"}:
        return True
    # Real Go modules must have a dot in the first path element.
    return bool(first) and "." not in first


def escape_go_module_path(path: str) -> str:
    """
    Case-encode a Go module path for the goproxy protocol.

    Uppercase letters become ``!`` plus lowercase so the proxy can be served
    from a case-insensitive filesystem. See
    https://go.dev/ref/mod#goproxy-protocol

        >>> escape_go_module_path("github.com/Azure/go-autorest")
        'github.com/!azure/go-autorest'
        >>> escape_go_module_path("gitea.dev")
        'gitea.dev'
    """
    escaped = []
    for char in path:
        if "A" <= char <= "Z":
            escaped.append("!")
            escaped.append(char.lower())
        else:
            escaped.append(char)
    return "".join(escaped)


def get_golang_versions(purl: PackageURL, logger: Callable = None) -> Optional[Set[str]]:
    """
    Return published version strings for a golang ``purl``.

    Standard library PURLs (``pkg:golang/stdlib``, ``pkg:golang/cmd/go``)
    use Go releases from ``https://go.dev/dl/?mode=json&include=all``.
    Values look like ``1.25.11`` (the ``go`` prefix is stripped) so they
    match vulndb ranges such as ``vers:golang/<1.25.11|>=1.26.0-0``.

    Other modules use ``GET https://proxy.golang.org/{module}/@v/list``
    and do not fetch ``.info``. A listed tag with no ``.info`` file, for
    example Traefik ``v3.0.0-beta1``, is kept instead of aborting the list.

    Returned strings have a leading ``v`` stripped::

        list line "v3.0.0" -> "3.0.0"
    """
    module = golang_module_from_purl(purl)
    if not module:
        return set()

    if is_go_standard_library_module(module):
        try:
            return fetch_go_release_versions()
        except Exception as e:
            if logger:
                logger(
                    f"Error while fetching Go releases for {purl!s}: {e!r} \n {traceback_format_exc()}",
                    level=logging.ERROR,
                )
            return set()

    try:
        list_text = fetch_golang_version_list(module)
    except Exception as e:
        if logger:
            logger(
                f"Error while fetching known versions for {purl!s}: {e!r} \n {traceback_format_exc()}",
                level=logging.ERROR,
            )
        return set()

    if list_text is None:
        if logger:
            logger(
                f"Go module not found on proxy.golang.org: {module}",
                level=logging.WARNING,
            )
        return set()

    versions_found = set()
    for line in list_text.splitlines():
        version = line.split()[0].strip() if line.strip() else ""
        if version:
            versions_found.add(version.lstrip("vV"))
    return versions_found


def fetch_go_release_versions() -> Set[str]:
    """
    Return published Go toolchain versions from go.dev.

    Used for ``stdlib``, ``cmd/go``, ``runtime``, and other std packages.
    The JSON looks like ``{"version": "go1.25.11"}``; we store ``1.25.11``.
    Results are cached for the process so unfurl does not refetch for every
    stdlib impact.
    """
    global _GO_RELEASE_VERSIONS
    if _GO_RELEASE_VERSIONS is not None:
        return _GO_RELEASE_VERSIONS

    response = requests.get(GO_RELEASES_URL, timeout=30)
    response.raise_for_status()
    versions_found = set()
    for release in response.json() or []:
        version = (release.get("version") or "").strip()
        if version.lower().startswith("go"):
            version = version[2:]
        if version:
            versions_found.add(version)
    _GO_RELEASE_VERSIONS = versions_found
    return versions_found


def fetch_golang_version_list(module: str) -> Optional[str]:
    """
    Return the ``/@v/list`` body for ``module``, or None if it is not on the proxy.

    The first request uses the full path. On 404, trailing segments are
    dropped so a package path can resolve to its module. Walk stops at VCS
    hosts (``github.com``) which are not modules.

    Examples:

    - ``github.com/traefik/traefik/v3`` -> that module's list (major version
      suffix is kept; fetchcode used to trim it).
    - ``github.com/foo/mod/internal/pkg`` 404s, then ``.../mod/internal``,
      then ``github.com/foo/mod`` until a list is found.
    - ``gitea.dev`` is a one-segment vanity module and is queried as-is.
    - ``github.com`` alone is never queried.
    """
    parts = [part for part in module.split("/") if part]
    while parts:
        candidate = "/".join(parts)
        if candidate in GO_VCS_ROOTS:
            return None
        url = f"{GOPROXY_URL}/{escape_go_module_path(candidate)}/@v/list"
        response = requests.get(url, timeout=30)
        if response.status_code == 404:
            parts.pop()
            continue
        response.raise_for_status()
        return response.text
    return None
