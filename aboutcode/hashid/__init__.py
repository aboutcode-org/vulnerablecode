#
# Copyright (c) nexB Inc. and others. All rights reserved.
# Portions Copyright (c) The Python Software Foundation
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0 and Python-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from hashlib import sha256
from math import ceil
from pathlib import Path
from typing import Union
from urllib.parse import quote
from uuid import uuid4

from packageurl import PackageURL
from packageurl import normalize_qualifiers
from packageurl import normalize_subpath

__version__ = "0.3.0"

"""
General purpose utilities to create content-defined, hash-based paths to store
Package data keyed by PURL.

The approach is to distribute the many data files for a package in multiple
directories stored in multiple Git repositories, so that each directory and repo
is not too big, with not too many files, spread roughly evenly across all the
directories and repositories. At the same time the construction is such that it
is possible to access a single data file across all these directories and Git
repositories knowing only its package PURL.

Multiple directories are needed to store many package metadata files to avoid
directories with too many files in the same directory, which makes every
filesystem performance suffer. Typically a max of about 10,000 files in a
directory is a decent target.

We also need multiple Git repositories to avoid very big repositories that are
impractical to use. We want each repo to be under the common limits of public
repository hosting services, like GitHub and its 5GB limit. Typicaly a maximum
size of 5GB and a target size of about 1GB of compressed content makes the most
sense. We store text and Git combination of XDiff, XDelta a zlib compression
typically can reduce the stored size by about 5, meaning that a 1GB repo may
contain about 5GB actual uncompressed text.

To distribute files roughly evenly across repositories and directories and still
using PURL as a key, we use a hash computed on the PURL to create repositories
and directory names.

With this approach, it becomes possible to distribute the data across many Git
repositories and directories and still access each data file directly by taking
a PURL and computing a direct path and URL to an actual data file, such as a
ScanCode scan.

We use this hierarchy of git repos:

    cluster (name for a data kind)
    repo (name with a kind, type, and PURL-based hash)
        -> directory name (kind, type, and PURL-based hash)
            -> PURL ns/name/version (no ns segment if this does not apply)
                -> PURL qualifiers+subpath

For instance, for a cluster about purl versions::

    aboutcode-purls: cluster name. This is a repo with config files to describe it
        aboutcode-cluster-config.yml: the cluster config file

    aboutcode-purls-gem-0000/ : repo name (0000 is on the first PURL hash of the range stored in this repo's dirs)
        purls-gem-0107/ : dir name composed of kind+type+hashid
            random_password_generator/purls.yml : path to a list of PURLs for the gem named random_password_generator

If the base URL for the cluster is at this GitHub org: aboutcode-data, then the
URL to the purls.yml file is inferred this way:

https://github.com/aboutcode-data/aboutcode-purls-gem-0000/blob/main/purls-gem-0107/gem/random_password_generator/purls.yml

Each directory may store specific data files, such as a list of PURLs with
version, ScanCode scans, using conventional filenames so they can be retrieved
directly.

To recap:

* Repo: A repo is a group of related directories, like for all the npms with a
  PURL hash of 0000 to 0123, where we store npm metadata files for each PURL.

* Cluster: A consistent set of repos for the same data kind, covering all or
  many package types is called a cluster. All repos in a cluster share the same
  name prefix. Clusters are focused on a data kind, for example a cluster of Git
  repos with all the package versions (list of PURLs) and medatata files, and
  another cluster for all the ScanCode scans.

These clusters align with the needs of users: for example, a user using only
vulnerability data for Java and JavaScript may not care directly for Haskell
metadata. Or may care only for another kind of data like fingerprints.

The PURL hashid consist of a SHA256 hash computed on a canonical PURL string (no
version, qualifiers or subpath) keeping up 1024 values, from 0000 to 1023 (e.g.,
modulo 1024)

Based on this hashid and the kind and type, directories are grouped in one or
more Git reposities of a cluster, based on a cluster-specific number of
directories of a type per Git repo.

For small ecosystems with few packages, like luarocks or swift, a single Git
repo may be enough to store all the data. There, a luarocks cluster of repos
will have a single Git repo, with 1024 root directories.

At the other end of the spectrum, a package type with many packages like npm may
need 1024 Git repositories to store all the metadata. In this case a npm cluster
of repos will have 1024 Git repos, each with a single root directory.

We can also rebalance a cluster, like starting to store the data in a cluster
with a single Git repository, and later splitting to more repos without loosing
the ability to address data files directly just knowing a PURL and without
having to rename all the files and paths.

In our scheme, the directory names are stable and do not change, the only thing
that changes are the repo names when more repos are created from a split, when
the size of a Git repo grows too large.

When a split to occur, we perform these operations:
- lock the cluster as "read-only" for the duration of a split operation.

- copy existing Git repos to be split to new repos based on the new number of
directories per repo.

- filter Git history in existing and new repos to keep only the history related
to the directories stored in a given repo.

- update the cluster config file in Git repo 0000 with the new number of
directories

- push new Git and existing Git repos

- unlock the cluster

It may even be possible to continue writing to a cluster as long as writing is
done in two places until the split is completed. In practice split should be
reasonbly rare and reasonably fast making this a lesser issue.

Furthermore, we can start with reasonable assumptions wrt. the size of each
cluster, as a number of directory per Git repo using these starting values:

1. Super Large Ecosystem (~5M packages)
- one dir per repo, yielding 1,024 repos
- github, npm

2. Large Ecosystem (~500K packages)
- eight dirs per repo, yielding 128 repos
- golang, maven, nuget, perl, php, pypi, ruby, huggingface

3. Medium Ecosystem (~50K packages)
- 32 dirs per repo, yielding 32 Git repositories
- alpm, bitbucket, cocoapods, composer, deb, docker, gem, generic,
  mlflow, pub, rpm, cargo

4. Small Ecosystem (~2K packages)
- 1,024 directories in onegit repository
- all others

See also original approach:
- https://github.com/aboutcode-org/federatedcode/issues/3#issuecomment-2388371726

We can have multiple clusters:
- for one package type
- to store data across many package types, like for vulnerabilities and advisories
- for one or more kind of data, like just the PURL versions, or the original
  metadata or the high level scans, scans with file details, reachability slices
  or fingerprints.

For instance, say we want a cluster to store all the npm PURLs. As of 2025-10,
npm hosts about 4M unique package names (and roughly 20 versions per name on
average with ~80M updates in total in https://replicate.npmjs.com/). Storing 4M
names takes about 100MB uncompressed. Adding versions would take about 2GB
uncompressed. This means that we can store comfortably all npm PURLs in a single
repository size-wise, but we may want to use more repositories anyway as storing
4M directories and purls.yml files in a single repo will not be a happy event,
so using 32 repos with 32 dirs or 64 repos with 16 dirs may be a better
approach.


Naming convention for repos:
   maintainer-purl_type-data_kind-repo_number

The repo_number is always the 1st repo of range of directory hashid





1024 directories from 0000 to 1023
    package-type
        package namespace/name or name
            purls.yml
            vulnerabilities.yml
            advisories.yml
            <version>
                possibly subdirectories?

Each cluster meta repo contains a configuration file that describes
its content and the number of directories per Git repos.

Tools need to check the cluster configuration file on a regular basis to use the
latest configuration.


The aboutcode-cluster-config.yml is a config file that minimally tells
  - what this data cluster is about
  - the number of dirs per repo in this cluster


aboutcode-cluster-config.yml fields
---------------------------------------
    base_url: base URL for this cluster of repos: https://github.com/aboutcode-data
    cluter_name_prefix: a unique prefix name for this base URL : aboutcode-purls
    number_of_dirs: 1024 (default)
    number_of_repos: 1 (default)
    # numbers_of_dirs_per_repo: number_of_dirs / number_of_repos
    # The number of directories in each repos can be any power of 2 from 0 to
    # 1024: 2**0: 1, 2, 4, 8, 16, 2**5: 32, 64, 128, 2**8: 256, 512, or 2**10:
    # 1024.

    purl_types: list of purl types stored in this cluster or * for all types.
        Implied default to *

    data_kind: a string that depicts the kind of data stored in this group of repos
        purls
        metadata
        api_metafiles
        vulnerablecode_advisories
        vulnerablecode_vulnerabilities
        scancode_scans
        scancode_fingerprints
        atom_slices
        sboms

    maintainer:
      name:
      email:
      url:
"""

PACKAGE_REPOS_NAME_PREFIX = "aboutcode-packages"

KIND_PURLS_FILENAME = "purls.yml"
KIND_VULNERABILITIES_FILENAME = "vulnerabilities.yml"


def get_package_base_dir(purl: Union[PackageURL, str]):
    """
    Return the base path to a Package directory (ignoring version) for a purl
    """
    if isinstance(purl, str):
        purl = PackageURL.from_string(purl)

    path_elements = package_path_elements(purl)
    phash, core_path, _pversion, _extra_path = path_elements
    return Path(f"{PACKAGE_REPOS_NAME_PREFIX}-{purl.type}-{phash}") / core_path


def get_package_purls_yml_file_path(purl: Union[PackageURL, str]):
    """
    Return the path to a Package purls.yml YAML for a purl.
    """
    return get_package_base_dir(purl) / KIND_PURLS_FILENAME


def get_package_vulnerabilities_yml_file_path(purl: Union[PackageURL, str]):
    """
    Return the path to a Package vulnerabilities.yml YAML for a purl.
    """
    return get_package_base_dir(purl) / KIND_VULNERABILITIES_FILENAME


# This is an initial tiering by type system for storing package metadata.
# The tiers are as follows:
# 1. Super Large Ecosystem (~5M packages): 1,024 git repositories
# 2. Large Ecosystem (~500K packages): 128 git repositories
# 3. Medium Ecosystem (~50K packages): 16 repositories
# 4. Small Ecosystem (~2K packages): 1 git repository
# See https://github.com/aboutcode-org/federatedcode/issues/3#issuecomment-2388371726
NUMBER_OF_REPOS_BY_ECOSYSTEM = {
    # Super Large Ecosystem
    "github": 1024,
    "npm": 1024,
    # Large Ecosystem
    "golang": 128,
    "maven": 128,
    "nuget": 128,
    "perl": 128,
    "php": 128,
    "pypi": 128,
    "ruby": 128,
    # Medium Ecosystem
    "alpm": 16,
    "bitbucket": 16,
    "cargo": 16,
    "cocoapods": 16,
    "composer": 16,
    "deb": 16,
    "docker": 16,
    "gem": 16,
    "generic": 16,
    "huggingface": 16,
    "mlflow": 16,
    "pub": 16,
    "rpm": 16,
    # Small Ecosystem
    "bitnami": 1,
    "conan": 1,
    "conda": 1,
    "cpan": 1,
    "cran": 1,
    "hackage": 1,
    "hex": 1,
    "luarocks": 1,
    "swift": 1,
}


def package_path_elements(
    purl: Union[PackageURL, str], 
    default_number_of_repos: int =1,
):
    """
    Return a 4-tuple of POSIX path strings from the ``purl`` string or object.
    
    The tuple members are: (purl_hash, core_path, purl.version, extra_path)
    These members can be joined using a POSIX "/" path separator to store
    package data distributed evenly in many directories, where package data of
    the same package is co-located in the same directory.

    The storage scheme is designed to create this path structure:

    <short-purl-hash> : top level directory or repository
      <type>/<namespace>/<name> : sub directories
        purls.yml : YAML file with known versions for this package ordered
           from oldest to newest

        vulnerabilities.yml : YAML file with known vulnerabilities affecting
           (and fixed by) this package

        <version> : one sub directory for each version
          metadata.yml : ABOUT YAML file with package origin and license metadata for this version
          scancode-scan.yml : a scancode scan for this package version
          foo-scan.yml : a scan for this package version created with tool foo
          sbom.cdx.1.4.json : a CycloneDX SBOM
          sbom.cdx.1.5.json : a CycloneDX SBOM
          sbom.spdx.2.2.json : a SPDX SBOM
          .... other files

          <extra_path> : one sub directory for each quote-encoded <qualifiers#subpath> if any
            metadata.yml : ABOUT YAML file with package origin and license metadata for this version
            scancode-scan.yml : a scancode scan for this package version
            foo-scan.yml : a scan for this package version created with tool foo
            sbom.cdx.1.4.json : a CycloneDX SBOM
            ... other files

    Some examples:

    We keep the same prefix for different versions::

    >>> package_path_elements("pkg:pypi/license_expression@30.3.1")
    ('50', 'pypi/license-expression', '30.3.1', '')
    >>> package_path_elements("pkg:pypi/license_expression@10.3.1")
    ('50', 'pypi/license-expression', '10.3.1', '')

    We encode with quotes, avoid double encoding of already quoted parts to make subpaths easier
    for filesystems::

    >>> package_path_elements("pkg:pypi/license_expression@30.3.1?foo=bar&baz=bar#sub/path")
    ('50', 'pypi/license-expression', '30.3.1', 'baz%3Dbar%26foo%3Dbar%23sub%2Fpath')

    >>> purl = PackageURL(
    ...     type="pypi",
    ...     name="license_expression",
    ...     version="b#ar/?30.3.2!",
    ...     qualifiers=dict(foo="bar"),
    ...     subpath="a/b/c")
    >>> package_path_elements(purl)
    ('50', 'pypi/license-expression', 'b%23ar%2F%3F30.3.2%21', 'foo%3Dbar%23a%2Fb%2Fc')
    """
    purl = as_purl(purl)

    bit_count = NUMBER_OF_REPOS_BY_ECOSYSTEM.get(purl.type, 0)
    purl_hash = get_purl_hash(purl=purl, _bit_count=bit_count)

    if ns := purl.namespace:
        ns_name = f"{ns}/{purl.name}"
    else:
        ns_name = purl.name

    extra_path = ""
    if pq := purl.qualifiers:
        # note that we percent-quote everything including the / character
        extra_path = quote_more(normalize_qualifiers(pq, encode=True))
    if psp := purl.subpath:
        psp = normalize_subpath(psp, encode=True)
        extra_path += quote_more(f"#{psp}")

    core_path = f"{purl.type}/{ns_name}"

    return purl_hash, core_path, quote_more(purl.version), extra_path


def quote_more(qs):
    """
    Return a quoted string from ``qs`` string by quoting all non-quoted
    characters ignoring already quoted characters. This makes the quoted string
    safer to use in a path.

    For example::
    >>> quote_more("foo")
    'foo'

    >>> quote_more("foo/bar")
    'foo%2Fbar'

    >>> quote_more("foo%2Fbar")
    'foo%2Fbar'
    """
    if not qs:
        return qs
    try:
        return quote(qs, safe="%")
    except Exception as e:
        raise Exception(f"Failed to quote_more: {qs!r}") from e

def as_purl(purl: Union[PackageURL, str]):
    """
    Return a  PackageURL from ``purl`` object or string.
    """
    if isinstance(purl, str):
        purl = PackageURL.from_string(purl)
    elif not isinstance(purl, PackageURL):
        raise ValueError(f"purl {purl!r} must be of type PackageURL or str, not {type(purl)!r}")
    return purl


def get_core_purl(purl: Union[PackageURL, str]):
    """
    Return a new "core" purl from a ``purl`` object or string, dropping version,
    qualifiers and subpath.
    """
    purl = as_purl(purl)
    purld = purl.to_dict()
    del purld["version"]
    del purld["qualifiers"]
    del purld["subpath"]
    return PackageURL(**purld)


def get_purl_hash(purl: Union[PackageURL, str], max_value: int=1024) -> str:
    """
    Return a hash string from a ``purl`` string or object.

    The PURL is normalized and we drop its version, qualifiers and subpath. This
    four characters hash string is the integer hash value between 0000 and 1023,
    left-padded with zeros.

    The function is designed to be easily portable across tech stacks and easy
    to implement in many programming languages:

    - the hash is based on sha256, available is all common languages,
    - the hash is based on the hash integer value between, left padded with 0
    - we use simple arithmetic on integer with modulo.

    Use these steps to compute a PURL hash:

    - Convert the PURL to a core PURL with only type, namespace and name.
    - Compute a SHA256 hash on that core PURL string encoded to bytes as UTF-8.
    - Convert that hash value to an integer.
    - Compute a modulo on that integer with the the max value.
      With default max_value of 1024, this yields an int between 0 and 1023.
    - Convert that integer to a 4-characters string left-padded with zero.

    For example::

    The hash does not change with version or qualifiers::
    >>> get_purl_hash("pkg:pypi/univers@30.12.0")
    '0009'
    >>> get_purl_hash("pkg:pypi/univers@10.12.0")
    '0009'
    >>> get_purl_hash("pkg:pypi/univers@30.12.0?foo=bar#sub/path")
    '0009'

    The hash is left padded with zeros::
    >>> get_purl_hash("pkg:pypi/expressionss")
    '0057'

    We use the canonical PURL. Here pypi normalization always uses dash for
    underscore ::

    >>> get_purl_hash("pkg:pypi/license_expression")
    '0050'
    >>> get_purl_hash("pkg:pypi/license-expression")
    '0050'

    Originally designed in :
    https://github.com/aboutcode-org/purldb/pull/235/files#diff-a1fd023bd42d73f56019d540f38be711255403547add15108540d70f9948dd40R154
    """

    core_purl_bytes = get_core_purl(purl).to_string().encode("utf-8")
    hash_bytes = sha256(core_purl_bytes).digest()
    # Convert bytes to integer, using big endian
    hash_int = int.from_bytes(hash_bytes, "big")
    # compute modulo max value
    short_int = hash_int % max_value
    # return as 4-char string left padded with 0
    return f"{short_int:04}"
