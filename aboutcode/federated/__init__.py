#
# Copyright (c) AboutCode and others. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about our open source projects.
#

from dataclasses import dataclass
from dataclasses import field as datafield
from hashlib import sha256
from pathlib import Path
from typing import Any
from typing import Iterable
from typing import Optional
from typing import Tuple
from typing import Union
from urllib.parse import quote
from urllib.parse import urlsplit

import requests
import saneyaml
import uritemplate
from packageurl import PackageURL
from packageurl import normalize_qualifiers
from packageurl import normalize_subpath
from packageurl import normalize_version

__version__ = "0.1.0"

"""
Federated data utilities to handle content-defined and hash-addressable Package
Federated data utilities goal is to handle content-defined and hash-addressable
Package data keyed by PURL stored in many Git repositories. This approach to
federate decentralized data is called FederatedCode.


Overview
========

The main design elements are:

1. Data Federation: A Data Federation is a database, representing a consistent,
non-overlapping set of data kind clusters (like scans, vulnerabilities or SBOMs)
across many package ecosystems, aka. PURL types.
A Federation is similar to a traditional database.

2. Data Cluster: A Data Federation contains Data Clusters, where a Data Cluster
purpose is to store the data of a single kind (like scans) across multiple PURL
types. The cluster name is the data kind name and is used as the prefix for
repository names. A Data Cluster is akin to a table in a traditional database.

3. Data Repository: A DataCluster contains of one or more Git Data Repository,
each storing datafiles of the cluster data kind and a one PURL type, spreading
the datafiles in multiple Data Directories. The name is data-kind +PURL-
type+hashid. A Repository is similar to a shard or tablespace in a traditionale
database.

4. Data Directory: In a Repository, a Data Directory contains the datafiles for
PURLs. The directory name PURL-type+hashid

5. Data File: This is a Data File of the DataCluster's Data Kind that is
stored in subdirectories structured after the PURL components::

   namespace/name/version/qualifiers/subpath:

- Either at the level of a PURL name: namespace/name,
- Or at the PURL version level namespace/name/version,
- Or at the PURL qualifiers+PURL subpath level.

A Data File can be for instance a JSON scan results file, or a list of PURLs in
YAML.

For example, a list of PURLs as a Data Kind  would stored at the name
subdirectory level::

    gem-0107/gem/random_password_generator/purls.yml

Or a ScanCode scan as a Data Kind at the version subdirectory level::

    gem-0107/npm/file/3.24.3/scancode.yml


Design
======

The core approach is to distribute the many datafiles for a package in multiple
directories stored in multiple Git repositories, so that each directory and repo
is not too big, with not too many files, and files are spread roughly evenly
across all the directories and repositories.

At the same time the design is such that it is possible to directly access a
single datafile across all these directories and Git repositories knowing only
its package PURL and resolve that to a URL to fetch a single datafile directly
by using the Git web interface (like on GitHub, Gitlab or gitweb)


Why not using a single Git repo?
--------------------------------

We need multiple Git repositories to avoid very big repositories that are
impractical to use. We want each repo to be under the common limits of public
repository hosting services, like GitHub and its 5GB limit. Typicaly a maximum
size of 5GB and a target size of about 1GB of compressed content makes the most
sense. We store text and Git combination of XDiff, XDelta a zlib compression
typically can reduce the stored size by about 5, meaning that a 1GB repo may
contain about 5GB actual uncompressed text.


Why not using a single dir in a repo?
--------------------------------------

Multiple directories are needed to store many package datafiles to avoid
directories with too many files in the same directory, which makes every
filesystem performance suffer. Typically a max of about 10,000 files in a
directory is a decent target.


Hash-based content distribution
-------------------------------

To distribute files roughly evenly across repositories and directories and still
using PURL as a key, we use a hashid derived from a hash computed on the PURL
string and use that to generate repositories and directory names.

It then becomes possible to distribute the data across many Git repositories and
directories evenly and compute a URL and path to access a datafile directly
from a PURL.


Object hierarchy
----------------

- **federation**: defined by its name and a Git repo with a config file with
  clusters configuration for data kind and PURL type parameters, enabling pointing
  to multiple repositories

    - **cluster**: identified by the data kind name, prefixing its data repos

        - **repo**: data repo (Git) identified by datakind+PURL-type+hashid

            - **directory**: dir in a repo, identified by PURL-type+PURL-hashid

                - **PURL path**: ns/name/version/extra_path derived from the PURL

                    - **datafile**: file storing the data as text JSON/YAML/XML

Example
-------

For instance, in the aboutcode data federation, for a cluster about purl
versions, we would have:

- data federation definition git repo, with its config file.
   - aboutcode-data/aboutcode-data
      - aboutcode-federation-config.yml

- data cluster repos name prefix is the data kind
    - aboutcode-data/purls

- data repository git repo, with a purl sub dir tree and datafile.
  The first repo name has a hash of 0000 which is the first PURL hashid of the
  range of PURL hashid stored in this repo's dirs.

    - aboutcode-data/purls-gem-0000/

- data directory, with a purl sub dir tree and datafile. The dir name
  composed of type+hashid.

    - aboutcode-data/purls-gem-0000/gem-0107/

- PURL subdirectory, and datafile, here list of PURLs for the gem named rails:
    - aboutcode-data/purls-gem-0000/gem-0107/rails/purls.yml

In this example, if the base URL for this cluster is at the aboutcode-data
GitHub organization, so the URL to the purls.yml datafile is inferred this way
based on the cluster config::

    https://github.com/
        aboutcode-data/purls-gem-0000/
            raw/refs/heads/main/
                gem-0107/rails/purls.yml


More Design details
===================

The DataCluster and Data kind design aligns with the needs of users: for
example, a user using only vulnerability data for Java and JavaScript may not
care directly for Haskell metadata. Or may care only for another kind of data
like fingerprints.

* DataCluster: A set of repos for only one data kind for many package types.

* Data Kind: Identifier for the kind of data stored in the datafile of
  DataCluster, like PURL versions, or the original API metadata files, or high
  level scans, or scans with file details, reachability slices, fingerprints, or
  vulnerability advisories and so on.

* Repository: A repo is a Git repo that stores a group of Directories of a
  DataCluster/data kind, like for all the npms with a PURL hash of 0000 to 1023,
  where we store npm metadata files for each PURL. All repo names in a cluster
  share the same data-kind prefix.

* Directory: Named after a PURL type and PURL hashid, it stores the datafiles
  for the PURLs that hash to that hashid.


Naming conventions
-------------------

- Federation: like aboutcode-data. Also the name of the config repo.

- DataCluster name prefix: data kind stored in that cluster, like "purls" or "scancode"

- For data repos: data kind + PURL type + PURL hashid like
  purls-npm-0512 or purls-scancode-scans-0000
  The PURL hashid is the first hashid of a range of hashid stored in that repo.

- For data dirs in a repo: PURL type + dir_number like npm-0513 or pypi-0000.
  The hashid is that of the PURLs whose data files are stored in that directory.


PURL Hashid
-----------

The PURL hashid is central to the design and is simply a number between 0 and
1023 (e.g., 1024 values which is a power of two).

It could be updated to up 8192 in the future, but 1024 is good enough to spread
files in multiple dirs.

The Core PURL is a PURL without version, subpath and qualifiers. We hash this
Core PURL as UTF-8-encoded bytes using SHA256.

The first few bytes of the SHA256 binary digest are converted to an integer
using little endian encoding, then converted modulo a max value of 1024 to yield
an integer converted to a 4-chars, zero-padded string between 0000 and 1023.

Based on this hashid and the data kind and PURL type, directories are grouped in
one or more Git reposities of a cluster, based on a cluster-defined number of
directories of a type per Git repo.


Example of repo and dir names
-----------------------------

With 4 dirs per repo, we get 256 repos, like these

purls-npm-0000
   npm-0000
   npm-0001
   npm-0002
   npm-0003

purls-npm-0004
   npm-0004
   npm-0005
   npm-0006
   npm-0007

purls-npm-0008
   npm-0008
   ... and so on


And with 512 dirs per repo, we get 2 repos:

purls-npm-0000
   npm-0000
   npm-0001
   npm-0002
   ...
   npm-0511

purls-npm-0512
   npm-0512
   npm-0513
   ...
   npm-1023


Git repos sizing assumptions for each ecosystems
-------------------------------------------------

For small ecosystems with few packages, like luarocks or swift, a single Git
repo or a few repos may be enough to store all the data of a kind. There, a
luarocks cluster of repos will have a single Git repo, with 1024 root
directories.

At the other end of the spectrum, a package type with many packages like npm may
need 1024 Git repositories to store all the metadata. In this case a npm cluster
of repos will have 1024 Git repos, each with a single root directory.

We can start with reasonable assumptions wrt. the size of each cluster, as a
number of directory per Git repo and the volume of data we would store in each
using these starting values:

1. For super large ecosystems (with ~5M packages):

- one dir per repo, yielding 1,024 repos
- github, npm

2. For large ecosystems (with ~500K packages)

- eight dirs per repo, yielding 128 repos
- golang, maven, nuget, perl, php, pypi, ruby, huggingface

3. For medium ecosystems (with ~50K packages)

- 32 dirs per repo, yielding 32 Git repositories
- alpm, bitbucket, cocoapods, composer, deb, docker, gem, generic,
  mlflow, pub, rpm, cargo

4. For small ecosystem (with ~2K packages)

- 1,024 directories in one git repository
- all others

For instance, say we want a cluster to store all the npm PURLs. As of 2025-10,
npm hosts about 4M unique package names (and roughly 20 versions per name on
average with ~80M updates in total in https://replicate.npmjs.com/). Storing 4M
names takes about 100MB uncompressed. Adding versions would take about 2GB
uncompressed. This means that we can store comfortably all npm PURLs in a single
repository size-wise, but we may want to use more repositories anyway as storing
4M directories and purls.yml files in a single repo will not be a happy event,
so using 32 repos with 32 dirs or 64 repos with 16 dirs may be a better
approach.

See also original post on the approach:
- https://github.com/aboutcode-org/federatedcode/issues/3#issuecomment-2388371726


Rebalancing and splitting a DataCluster repos
------------------------------------------------

We can rebalance a cluster, like when we first store the data in a cluster with
a single Git repository for a given PURL type, and later split this repo to more
repos, without loosing the ability to address datafiles directly just knowing a
PURL and without having to rename all the files and directories.

In this design, the directory names are stable and do not change as long as we
keep the default 1024 hash values for the PURL hashid. The only thing that
changes are the repo names when more repos are created from a split, when the
size of a Git repo grows too large.

When a split to occur, we should perform these operations:

- lock the cluster as "read-only" for the duration of a split operation. This is
  to signal to processes and tool that are updating the cluster that they cannot
  push new data to there yet. This could be done by updating the cluster config
  or the federation config.

- copy existing Git repos to be split to new repos based on the new number of
  directories per repo.

- filter Git history in existing and new repos to keep only the history related
  to the directories stored in a given repo.

- update the cluster config file in cluster Git repo with the new number of
  directories

- push new Git and existing Git repos

- unlock the cluster.

We may need to keep the old and new Clusters around too, and may need to add a
simple DataCluster version suffix in Cluster names, and a way to redirect from an
old frozen, inactive DataCluster to a new rebalanced one.

It may even be possible to continue writing to a cluster as long as writing is
done in two places until the split is completed. In practice split should be
reasonably rare and reasonably fast, making this a lesser issue.

It is also possible to change the PURL hashid range for a DataCluster, say going
from 1024 to 2049, 4096 or 8192. This would imply moving all the files around
are the directory structure would change from the new hashids. This is likely
to be an exceptional operation.

"""

PACKAGE_REPOS_NAME_PREFIX = "aboutcode-packages"

KIND_PURLS_FILENAME = "purls.yml"
KIND_VULNERABILITIES_FILENAME = "vulnerabilities.yml"


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


def get_package_base_dir(purl: Union[PackageURL, str]):
    """
    Return the base path to a Package directory (ignoring version) for a purl
    """
    if isinstance(purl, str):
        purl = PackageURL.from_string(purl)

    path_elements = package_path_elements(purl)
    phash, core_path, _pversion, _extra_path = path_elements
    return Path(f"{PACKAGE_REPOS_NAME_PREFIX}-{purl.type}-{phash}") / core_path


@dataclass
class DataFederation:
    """
    A data federation is the root object and holds the configuration defining its
    data clusters, data kinds, PURL types and data repositories.
    """

    # Hardcoded Aboutcode known "root" federation URL that is the parent all of
    # all Git remote repositories
    ABCD_FED_ROOT_URL = "https://github.com/aboutcode-data"
    # and federation name
    ABCD_FED_NAME = "aboutcode-data"

    CONFIG_FILENAME = "aboutcode-federated-config.yml"

    # name for this federation. Used as the prefix for all repos
    name: str
    # Root dir of all federation local data, like all Git repos checkout.
    local_root_dir: Path = None
    # root URL for all Git repos for this federation
    remote_root_url: str = None
    description: Optional[str] = datafield(default="")
    documentation_url: Optional[str] = datafield(default="")
    # SPDX license expression
    data_license: Optional[str] = datafield(default="")
    data_maintainers: list["DataMaintainer"] = datafield(default_factory=list)

    # List of DataCluster objects
    # Each cluster is for a single, unique data kind in a federation.
    data_clusters: list["DataCluster"] = datafield(default_factory=list, repr=False)

    _data_clusters_by_data_kind: dict[str, "DataCluster"] = datafield(
        default_factory=dict, repr=False, init=False
    )

    def __post_init__(self):
        self.populate_clusters()

    def populate_clusters(self):
        self._data_clusters_by_data_kind = {
            cluster.data_kind: cluster for cluster in self.data_clusters
        }

    def add_cluster(self, cluster):
        self._data_clusters_by_data_kind[cluster.data_kind] = cluster
        self.data_clusters = list(self._data_clusters_by_data_kind.values())

    @property
    def local_config_dir(self):
        # this is also the directory of the config Git repo checkout
        return self.local_root_dir / self.name

    @property
    def local_config_file(self):
        return self.local_config_dir / self.CONFIG_FILENAME

    @classmethod
    def remote_config_file_url(
        cls,
        remote_root_url: str,
        federation_name: str,
    ):
        """Return a URL to directly download the federation config file"""
        return build_direct_federation_config_file_url(
            remote_root_url=remote_root_url,
            federation_name=federation_name,
            config_filename=cls.CONFIG_FILENAME,
        )

    @property
    def config_repo(self) -> "GitRepo":
        """
        Return the GitRepo that contains the configuration for this federation.
        """
        return GitRepo(
            name=self.name,
            local_root_dir=self.local_root_dir,
            remote_root_url=self.remote_root_url,
        )

    @classmethod
    def from_dict(
        cls,
        data: dict,
        local_root_dir: Path = None,
        remote_root_url: str = None,
    ) -> "DataFederation":
        """
        Return a DataFederation from a configuration mapping.
        """
        name = data["name"]

        rru = data.get("remote_root_url")
        if remote_root_url and rru != remote_root_url:
            raise TypeError(f"Inconsistent remote_root_urls: {rru!r} and {remote_root_url!r}")

        data_clusters = data.get("data_clusters") or []

        data_kinds = sorted(c["data_kind"] for c in data_clusters)
        if data_kinds != sorted(set(data_kinds)):
            raise TypeError(f"Duplicated data kinds: {data_kinds}")

        data_clusters = [DataCluster.from_dict(data=cluster) for cluster in data_clusters]

        data_maintainers = data.get("data_maintainers") or []
        data_maintainers = [DataMaintainer(**mnt) for mnt in data_maintainers]

        return cls(
            name=name,
            local_root_dir=local_root_dir and Path(local_root_dir) or None,
            remote_root_url=remote_root_url,
            description=data.get("description"),
            documentation_url=data.get("documentation_url"),
            data_license=data.get("data_license"),
            data_maintainers=data_maintainers,
            data_clusters=data_clusters,
        )

    @classmethod
    def load(cls, name: str, local_root_dir: Path, remote_root_url: str = None) -> "DataFederation":
        """
        Return an existing DataFederation loaded from ``local_root_dir`` using
        the existing configuration file at its conventional location.
        """
        lrd = Path(local_root_dir).resolve()
        lcf = lrd / name / cls.CONFIG_FILENAME
        return cls.from_yaml_config(
            name=name,
            text=lcf.read_text(),
            remote_root_url=remote_root_url,
            local_root_dir=lrd,
        )

    @classmethod
    def from_url(
        cls,
        name: str,
        remote_root_url: str,
        local_root_dir: Path = None,
    ) -> "DataFederation":
        """
        Return a DataFederation loaded from a remote configuration file.
        """
        rcf_url = build_direct_federation_config_file_url(
            remote_root_url=remote_root_url,
            federation_name=name,
            config_filename=cls.CONFIG_FILENAME,
        )
        headers = {"User-Agent": "AboutCode/FederatedCode"}
        response = requests.get(url=rcf_url, headers=headers)
        if not response.ok:
            raise Exception(f"Failed to fetch Federation config: {rcf_url}")

        return cls.from_yaml_config(
            name=name,
            text=response.text,
            remote_root_url=remote_root_url,
            local_root_dir=local_root_dir,
        )

    @classmethod
    def from_yaml_config(
        cls,
        name: str,
        text: str,
        local_root_dir: Path = None,
        remote_root_url: str = None,
    ) -> "DataFederation":
        """
        Return a DataFederation loaded from a YAML configuration text.
        """
        data = saneyaml.load(text)

        if data["name"] != name:
            raise TypeError(
                f"Inconsistent federation name {name!r} " f"with YAML config text: {text!r}"
            )

        lrd = local_root_dir and Path(local_root_dir) or None
        return cls.from_dict(data=data, local_root_dir=lrd, remote_root_url=remote_root_url)

    def to_dict(self):
        """
        Return a mapping for this federation configuration.
        """
        return dict(
            name=self.name,
            remote_root_url=self.remote_root_url,
            description=self.description,
            documentation_url=self.documentation_url,
            data_license=self.data_license,
            data_maintainers=[m.to_dict() for m in self.data_maintainers],
            data_clusters=[dc.to_dict() for dc in self.data_clusters],
        )

    def to_yaml(self):
        """
        Return a YAML text string for this federation configuration.
        """
        return saneyaml.dump(self.to_dict())

    def dump(self):
        """
        Write federation configuration file as YAML.
        """
        if not (lrd := self.local_root_dir):
            raise ValueError(f"Cannot dump without a local_root_dir : {lrd!r}")
        Path(self.local_config_file).write_text(self.to_yaml())

    @classmethod
    def init(cls, name, local_root_dir, remote_root_url=None) -> "DataFederation":
        """
        Initialize a new DataFederation in local_root_dir. Fetch the remote
        config repo if remote_root_url is provided and the repo exists there.
        """
        local_root_dir = Path(local_root_dir).resolve()
        local_config_repo_dir = local_root_dir / name
        # create dir if needed
        # or check if this is a git repo?
        # if not init git repo
        # create basic config and save that in the config file
        if remote_root_url:
            # TODO: clone or sync? repo in local_config_repo_dir
            # raise NotImplementedError("remote_repo_url is not yet supported.")
            pass

        raise NotImplementedError()

    def git_init(self):
        """
        Create all Git repos for this federation as needed. Sets the remote
        if the remote_root_url is defined.
        """
        raise NotImplementedError()

    @classmethod
    def bootstrap(cls, local_root_dir) -> "DataFederation":
        """
        Return the root, seed DataFederation from AboutCode, bootstrapping in
        local_root_dir.
        """
        return DataFederation.init(
            name=cls.ABCD_FED_NAME,
            local_root_dir=local_root_dir,
            remote_root_url=cls.ABCD_FED_ROOT_URL,
        )

    def get_cluster(self, data_kind: str) -> "DataCluster":
        """
        Return a DataCluster for this data kind or None.
        """
        return self._data_clusters_by_data_kind.get(data_kind)

    def get_datafile_download_url(self, data_kind: str, purl: Union[str, PackageURL]) -> Path:
        """
        Return the direct download URL to the data file for a data kind given a
        PURL, or None.
        """
        cluster = self.get_cluster(data_kind=data_kind)
        return cluster.get_datafile_download_url(purl=purl)

    def get_local_datafile(self, data_kind: str, purl: Union[str, PackageURL]) -> "LocalDataFile":
        """
        Return a LocalDataFile for a data kind given a PURL, or None.
        """
        cluster = self.get_cluster(data_kind=data_kind)
        return cluster.get_datafile_local_path(purl=purl)


@dataclass
class LocalDataFile:
    """A local data file stored optionally in a GitRepo"""

    path: Path
    git_repo: "GitRepo" = None


@dataclass(order=True)
class DataCluster:
    """
    AboutCode Federation DataCluster.
    """

    # The name for the data kind stored in this data cluster. There is only one
    # per cluster and the name is unique in a federation.
    # this is the name of cluster
    data_kind: str

    # a URI template to build the path to the datafile for this data kind.
    # this is the path relative to the root of a cluster directory. It does not
    # include directory and repository.
    #
    # For instance for a purls.yml file stored for each package:
    #  {/namespace}/{name}/purls.yml
    #
    # For a scancode.json file stored for each package version:
    #  {/namespace}/{name}/{version}/scancode.json
    datafile_path_template: str

    # list of unique PurlTypeConfig for types stored in this data cluster.
    # "default" is the type that applies to all types not listed here by default
    # and it will be added if not provided.
    purl_type_configs: list["PurlTypeConfig"] = datafield(
        default_factory=list,
        repr=False,
    )

    # JSON or XML schema URL for the file format of this data kind if available
    data_schema_url: Optional[str] = datafield(default="")

    # description of the data kind format, and description of how this data kind
    # is created: which tool, option, etc for instance, a short description of a
    # tool and the tool options, like a scancode toolkit command line option, or
    # the URL to an API whe we fetch API data
    description: Optional[str] = datafield(default="")

    documentation_url: Optional[str] = datafield(default="")

    # SPDX license expression
    data_license: Optional[str] = datafield(default="")

    data_maintainers: list["DataMaintainer"] = datafield(default_factory=list)

    # mapping of {purl_type: DataRepository} for the repos stored in this data
    # cluster. This is auto populated and not serialized in the config file.
    _data_repositories_by_purl_type: dict[str, "DataRepository"] = datafield(
        default_factory=dict,
        init=False,
        repr=False,
    )

    # mapping of {purl_type: PurlTypeConfig} for the repos stored in this data
    # cluster. This is auto populated and not serialized in the config file.
    _configs_by_purl_type: dict[str, "PurlTypeConfig"] = datafield(
        default_factory=dict,
        init=False,
        repr=False,
    )

    def __post_init__(self):
        self.populate_repos()
        self.populate_configs()

    def populate_repos(self):
        """
        Populate the DataRepository for this DataCluster data kind and PurlTypeConfig.
        """
        kind = self.data_kind
        drbpt = self._data_repositories_by_purl_type

        for ptc in self.purl_type_configs:
            drbpt[ptc.purl_type] = [repo for repo in ptc.get_repos(data_kind=kind)]

    def populate_configs(self):
        for ptc in self.purl_type_configs:
            self._configs_by_purl_type[ptc.purl_type] = ptc

    @classmethod
    def from_dict(cls, data: dict) -> "DataCluster":
        ptcs = [PurlTypeConfig(**pt) for pt in data.get("purl_type_configs", [])]

        ptypes = sorted(pt.purl_type for pt in ptcs)
        if ptypes != sorted(set(ptypes)):
            raise ValueError(f"Duplicate purl types: {ptypes!r}")

        if "default" not in ptypes:
            ptcs.append(PurlTypeConfig.default_config())

        data_maintainers = data.get("data_maintainers") or []
        data_maintainers = [DataMaintainer(**mnt) for mnt in data_maintainers]

        return cls(
            data_kind=data["data_kind"],
            datafile_path_template=data.get("datafile_path_template"),
            purl_type_configs=ptcs,
            data_schema_url=data.get("data_schema_url"),
            description=data.get("description"),
            documentation_url=data.get("documentation_url"),
            data_license=data.get("data_license"),
            data_maintainers=data_maintainers,
        )

    def to_dict(self):
        return dict(
            data_kind=self.data_kind,
            datafile_path_template=self.datafile_path_template,
            purl_type_configs=[pt.to_dict() for pt in self.purl_type_configs],
            data_schema_url=self.data_schema_url,
            description=self.description,
            documentation_url=self.documentation_url,
            data_license=self.data_license,
            data_maintainers=[m.to_dict() for m in self.data_maintainers],
        )

    def split_cluster(self, number_of_repos, number_of_dirs):
        """
        Split the repositories of a cluster in more repositories and directories
        """
        raise NotImplementedError()

    def get_datafile_download_url(self, purl: Union[str, PackageURL]) -> str:
        """
        Return the direct download URL to the data file of the data kind stored
        in this cluster given a PURL.
        """
        raise NotImplementedError()

        purl = as_purl(purl)
        # FIXME: create as member
        purl_type_config_by_type = {ptc.purl_type: ptc for ptc in self.purl_type_configs}
        purl_type_config = purl_type_config_by_type(purl.type, self.default_config())

        ppe = package_path_elements(purl, max_value=purl_type_config.number_of_dirs)
        purl_hash, core_path, version, extra_path = ppe

        direct_url = None
        # construct a path based on path template
        # construct a URL
        return direct_url

    def get_local_datafile(self, purl: Union[str, PackageURL]) -> LocalDataFile:
        """
        Return a LocalDataFile of the data kind stored in this cluster given a
        PURL, or None
        """
        raise NotImplementedError()

    def get_config(self, purl_type: str) -> "PurlTypeConfig":
        """
        Return a PurlTypeConfig for this purl type.
        """
        if purl_type not in self._configs_by_purl_type:
            return self._configs_by_purl_type["default"]
        return self._configs_by_purl_type[purl_type]

    def get_datafile_relative_path(self, purl: Union[str, PackageURL]) -> str:
        """
        Return the datfile path relative to the root of a cluster directory
        given a PURL.
        """
        purl = as_purl(purl=purl)

        if not purl.version and "{version}" in self.datafile_path_template:
            raise ValueError(
                f"DataCluster '{self.data_kind}' needs PackageURL with version to generate path."
            )

        template = uritemplate.URITemplate(self.datafile_path_template)
        return template.expand(
            namespace=purl.namespace,
            name=purl.name,
            version=purl.version,
        )

    def get_repo_and_dir_hash(self, purl: Union[str, PackageURL]) -> Tuple[str, str]:
        """
        Return the repository hash and directory hash given a PURL.
        """
        purl = as_purl(purl=purl)
        ptc = self.get_config(purl.type)
        purl_hashid = compute_purl_hash(purl=purl)
        purl_hash = int(purl_hashid)
        repo_hash = purl_hash - (purl_hash % ptc.numbers_of_dirs_per_repo)
        return f"{repo_hash:04}", purl_hashid

    def get_datafile_repo_and_path(self, purl: Union[str, PackageURL]) -> Tuple[str, str]:
        """
        Return the repository name and relative path to the datafile of the data kind stored
        in this cluster given a PURL.
        """
        purl = as_purl(purl)
        repo_hash, dir_hash = self.get_repo_and_dir_hash(purl)
        relative_datafile_path = self.get_datafile_relative_path(purl)

        directory_name = f"{purl.type}-{dir_hash}"
        repository_name = f"{self.data_kind}-{purl.type}-{repo_hash}"
        datafile_path = f"{directory_name}{relative_datafile_path}"

        return repository_name, datafile_path


@dataclass
class PurlTypeConfig:
    """
    Configuration settings for a PURL type stored in a DataCluster
    """

    # Maximum number of dirs we can support
    # at 10Gb per dir, that would support 80TB
    MAX_NUMBER_OF_DIRS = 8192

    # purl type or "default" for a default that applies to all types
    purl_type: str

    # number of repos for this PURL type in a cluster
    number_of_repos: int = 1

    # number of dirs for this PURL type in a cluster. Also defines the max PURL
    # hash value.
    number_of_dirs: int = 1024

    def to_dict(self) -> dict[str, Any]:
        return dict(
            purl_type=self.purl_type,
            number_of_repos=self.number_of_repos,
            number_of_dirs=self.number_of_dirs,
        )

    def __post_init__(self):
        self.number_of_repos = int(self.number_of_repos)
        self.number_of_dirs = int(self.number_of_dirs)

        if not self.number_of_dirs or self.number_of_dirs > self.MAX_NUMBER_OF_DIRS:
            raise TypeError(
                f"number_of_dirs {self.number_of_dirs!r} "
                f"must be between 1 and {self.MAX_NUMBER_OF_DIRS} included"
            )

        if not is_valid_power_of_two(self.number_of_dirs):
            raise TypeError(f"number_of_dirs must be a power of 2, " f"not {self.number_of_dirs!r}")

        if not self.number_of_repos or self.number_of_repos > self.number_of_dirs:
            raise TypeError(
                f"number_of_repos {self.number_of_repos!r} must be between "
                f"1 and {self.number_of_dirs!r}"
            )

        if not is_valid_power_of_two(self.number_of_repos):
            raise TypeError(
                f"number_of_repos must be a power of 2, " f"not {self.number_of_repos!r}"
            )

    @property
    def numbers_of_dirs_per_repo(self) -> int:
        """
        Return the number of directories in each repos for this type.
        It can be any power of 2 from 1 to number_of_dirs (default to 1024)
        """
        return self.number_of_dirs // self.number_of_repos

    @property
    def hashids(self) -> list[str]:
        """
        Return a list of hashid 4-char strings for this PURL type.
        """
        # all possible hashids as 4-char strings padded with zeros
        return [f"{v:04}" for v in range(self.number_of_dirs)]

    def get_repos(self, data_kind: str) -> Iterable["DataRepository"]:
        """
        Yield DataRepository (populated with DataDirectory) for this PURL type.
        """
        purl_type = self.purl_type
        dirs_per_repo = self.numbers_of_dirs_per_repo
        # all possible hashids as 4-char strings padded with zeros
        hashids = self.hashids

        for i in range(0, self.number_of_dirs, dirs_per_repo):
            hashids_of_repo = hashids[i : i + dirs_per_repo]
            yield DataRepository.from_hashids(
                data_kind=data_kind,
                purl_type=purl_type,
                hashids=hashids_of_repo,
            )

    @classmethod
    def default_config(cls) -> "PurlTypeConfig":
        """
        Return the default used when nothing is specified for a type
        """
        return cls(
            purl_type="default",
            number_of_repos=1,
            number_of_dirs=cls.number_of_dirs,
        )

    @classmethod
    def large_size_configs(cls):
        """
        Return a list of initial PurlTypeConfig for common types to be used as
        template when configuring clusters from scratch for storing data of
        large size (scans, etc)
        """

        # This is an initial tiering by type system for storing package metadata
        # where the datafile would be large.
        # The tiers are as follows:
        # 1. Super Large Ecosystem (~5M packages): 1,024 git repositories
        # 2. Large Ecosystem (~500K packages): 128 git repositories
        # 3. Medium Ecosystem (~50K packages): 16 repositories
        # 4. Small Ecosystem (~2K packages): 1 git repository
        NUMBER_OF_REPOS_BY_PURL_TYPE = {
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
            # Small Ecosystem all use the default
            "default": 1,
        }
        return [
            cls(purl_type=pt, number_of_repos=nor, number_of_dirs=cls.number_of_dirs)
            for pt, nor in NUMBER_OF_REPOS_BY_PURL_TYPE.items()
        ]

    @classmethod
    def medium_size_configs(cls):
        """
        Return a list of initial PurlTypeConfig for common types to be used as
        template when configuring clusters from scratch for storing data of
        medium size (metadata files, etc.)
        """
        NUMBER_OF_REPOS_BY_PURL_TYPE = {
            # Super Large Ecosystem
            "github": 256,
            "npm": 256,
            # Large Ecosystem
            "golang": 32,
            "maven": 32,
            "nuget": 32,
            "perl": 32,
            "php": 32,
            "pypi": 32,
            "ruby": 32,
            # Medium Ecosystem
            "alpm": 8,
            "bitbucket": 8,
            "cargo": 8,
            "cocoapods": 8,
            "composer": 8,
            "deb": 8,
            "docker": 8,
            "gem": 8,
            "generic": 8,
            "huggingface": 8,
            "mlflow": 8,
            "pub": 8,
            "rpm": 8,
            # Small Ecosystem all use the default
            "default": 1,
        }
        return [
            cls(purl_type=pt, number_of_repos=nor, number_of_dirs=cls.number_of_dirs)
            for pt, nor in NUMBER_OF_REPOS_BY_PURL_TYPE.items()
        ]

    @classmethod
    def small_size_configs(cls):
        """
        Return a list of initial PurlTypeConfig for common types to be used as
        template when configuring clusters from scratch for storing data of
        medium size (purls, etc.)
        """
        NUMBER_OF_REPOS_BY_PURL_TYPE = {
            # Super Large Ecosystem
            "github": 128,
            "npm": 128,
            # Large Ecosystem
            "golang": 16,
            "maven": 16,
            "nuget": 16,
            "perl": 16,
            "php": 16,
            "pypi": 16,
            "ruby": 16,
            # Medium Ecosystem
            "alpm": 4,
            "bitbucket": 4,
            "cargo": 4,
            "cocoapods": 4,
            "composer": 4,
            "deb": 4,
            "docker": 4,
            "gem": 4,
            "generic": 4,
            "huggingface": 4,
            "mlflow": 4,
            "pub": 4,
            "rpm": 4,
            # Small Ecosystem all use the default
            "default": 1,
        }
        return [
            cls(purl_type=pt, number_of_repos=nor, number_of_dirs=cls.number_of_dirs)
            for pt, nor in NUMBER_OF_REPOS_BY_PURL_TYPE.items()
        ]


def cluster_preset():
    """
    Return a mapping of preset DataCluster by data kind for registered kinds.
    """
    clusters = [
        DataCluster(
            data_kind="purls",
            description="List of fully qualified PURL strings for a package, sorted by version.",
            datafile_path_template="{/namespace}/{name}/purls.yml",
            purl_type_configs=PurlTypeConfig.small_size_configs(),
            data_schema_url="",
            documentation_url="https://github.com/package-url/purl-spec/",
            data_license="CC-BY-4.0",
        ),
        DataCluster(
            data_kind="api_package_metadata",
            description="Raw API response datafiles for a package (ignoring versions). "
            "Each datafile path and schema is PURL type-specific "
            "and not documented here.",
            # FIXME: a POM is in XML, some metadata files may be code
            datafile_path_template="",
            purl_type_configs=PurlTypeConfig.large_size_configs(),
            data_schema_url="",
            documentation_url="",
            data_license="CC-BY-4.0",
        ),
        DataCluster(
            data_kind="api_package_version_responses",
            description="Raw API response datafiles for a package versions. "
            "Each datafile path and schema is PURL type-specific "
            "and not documented here.",
            # FIXME: a POM is in XML, some metadata files may be code
            datafile_path_template="",
            purl_type_configs=PurlTypeConfig.large_size_configs(),
            data_schema_url="",
            documentation_url="",
            data_license="CC-BY-4.0",
        ),
        DataCluster(
            data_kind="purldb",
            description="PurlDB normalized metadata datafiles for each package "
            "versions. Does not include fingerprints and symbols.",
            datafile_path_template="{/namespace}/{name}/{version}/purldb.json",
            purl_type_configs=PurlTypeConfig.large_size_configs(),
            data_schema_url="",
            documentation_url="",
            data_license="CC-BY-4.0",
        ),
        # legacy, moving to advisories instead
        DataCluster(
            data_kind="vulnerabilities",
            description="VulnerableCode vulnerabilities for each package. "
            "Also includes a separate vulnerabilities directory/",
            datafile_path_template="{/namespace}/{name}/vulnerabilities.json",
            purl_type_configs=[PurlTypeConfig.default_config()],
            data_schema_url="",
            documentation_url="",
            data_license="CC-BY-4.0",
        ),
        DataCluster(
            data_kind="security_advisories",
            description="VulnerableCode security advisories for each package version.",
            datafile_path_template="{/namespace}/{name}/{version}/advisories.yml",
            purl_type_configs=[PurlTypeConfig.default_config()],
            data_schema_url="",
            documentation_url="",
            data_license="CC-BY-4.0",
        ),
        DataCluster(
            data_kind="scancode_toolkit_scans",
            description="scancode toolkit scans for each package version.",
            datafile_path_template="{/namespace}/{name}/{version}/scancode-toolkit.json",
            purl_type_configs=PurlTypeConfig.large_size_configs(),
            data_schema_url="",
            documentation_url="",
            data_license="CC-BY-4.0",
        ),
        DataCluster(
            data_kind="scancode_fingerprints",
            description="scancode_fingerprints for each package version.",
            datafile_path_template="{/namespace}/{name}/{version}/scancode-fingerprints.json",
            purl_type_configs=PurlTypeConfig.large_size_configs(),
            data_schema_url="",
            documentation_url="",
            data_license="CC-BY-4.0",
        ),
        DataCluster(
            data_kind="cyclonedx14_sboms",
            description="CycloneDX v1.4 sboms for each package version",
            datafile_path_template="{/namespace}/{name}/{version}/cyclonedx-14.json",
            purl_type_configs=PurlTypeConfig.large_size_configs(),
            data_schema_url="",
            documentation_url="",
            data_license="CC-BY-4.0",
        ),
        DataCluster(
            data_kind="cyclonedx15_sboms",
            description="CycloneDX v1.5 sboms for each package version",
            datafile_path_template="{/namespace}/{name}/{version}/cyclonedx-15.json",
            purl_type_configs=PurlTypeConfig.large_size_configs(),
            data_schema_url="",
            documentation_url="",
            data_license="CC-BY-4.0",
        ),
        DataCluster(
            data_kind="cyclonedx16_sboms",
            description="CycloneDX v1.6 sboms for each package version",
            datafile_path_template="{/namespace}/{name}/{version}/cyclonedx-16.json",
            purl_type_configs=PurlTypeConfig.large_size_configs(),
            data_schema_url="",
            documentation_url="",
            data_license="CC-BY-4.0",
        ),
        DataCluster(
            data_kind="spdx2_sboms",
            description="SPDX version 2.x sboms for each package version",
            datafile_path_template="{/namespace}/{name}/{version}/spdx-2.json",
            purl_type_configs=PurlTypeConfig.large_size_configs(),
            data_schema_url="",
            documentation_url="",
            data_license="CC-BY-4.0",
        ),
        DataCluster(
            data_kind="atom_slices",
            description="Atom slices for each package version",
            datafile_path_template="{/namespace}/{name}/{version}/atom.json",
            purl_type_configs=PurlTypeConfig.large_size_configs(),
            data_schema_url="",
            documentation_url="",
            data_license="CC-BY-4.0",
        ),
        DataCluster(
            data_kind="atom_vulnerable_slices",
            description="Atom vulnerable_slices for each vulnerable package version",
            # FIXME: need to qualify these with an advisory / CVE?
            datafile_path_template="{/namespace}/{name}/{version}/atom-vulnerable.json",
            purl_type_configs=PurlTypeConfig.large_size_configs(),
            data_schema_url="",
            documentation_url="",
            data_license="CC-BY-4.0",
        ),
        DataCluster(
            data_kind="openssf_security_scorecards",
            description="OpenSSf security_scorecards for package",
            # FIXME: need to qualify these with an advisory / CVE?
            datafile_path_template="{/namespace}/{name}/security_scorecard.json",
            purl_type_configs=PurlTypeConfig.medium_size_configs(),
            data_schema_url="",
            documentation_url="",
            data_license="CC-BY-4.0",
        ),
    ]
    return {dc.data_kind: dc for dc in clusters}


@dataclass
class DataRepository:
    """
    A Data Repository (Git repo or local plain dir) in a DataCluster
    """

    data_kind: str
    purl_type: str
    start_hashid: str

    data_directories: list["DataDirectory"] = datafield(
        default_factory=list,
        repr=False,
    )

    @property
    def name(self):
        return f"{self.data_kind}-{self.purl_type}-{self.start_hashid}"

    @classmethod
    def from_hashids(
        cls,
        data_kind: str,
        purl_type: str,
        hashids: list[str],
    ) -> "DataRepository":

        """
        Return a new DataRepository to store ``data_kind`` of ``purl_type`` for
        a list of ``hashids``.
        """

        data_directories = [DataDirectory(purl_type=purl_type, hashid=hashid) for hashid in hashids]

        # always the 1st hashid of the range of hashid stored in that repo
        start_hashid = hashids[0]

        return cls(
            data_kind=data_kind,
            purl_type=purl_type,
            start_hashid=start_hashid,
            data_directories=data_directories,
        )

    @property
    def git_repo(self) -> "GitRepo":
        """
        Return the GitRepo that contains the data for this DataRepository.
        """
        return GitRepo(
            name=self.name,
            local_root_dir=self.local_root_dir,
            remote_root_url=self.remote_root_url,
        )


@dataclass
class DataDirectory:
    """
    A Data Directory in a Data Repository
    """

    purl_type: str
    hashid: str

    local_root_dir: Path = None

    def __post_init__(self):
        if len(self.hashid) != 4:
            raise TypeError(f"Invalid hashid length. Must be 4: {self.hashid!r}")

    @property
    def name(self):
        return f"{self.purl_type}-{self.hashid}"

    def local_dir_path(self, local_root_dir, repo_name) -> Union[Path, None]:
        return local_root_dir / repo_name / self.name


@dataclass
class DataMaintainer:
    """
    Person or org that maintains a data federation or cluster
    """

    name: str
    email: Optional[str] = None
    url: Optional[str] = None

    def to_dict(self):
        return dict(
            name=self.name,
            email=self.email,
            url=self.url,
        )


@dataclass
class GitRepo:
    """
    A Git Repo.
    """

    # the name of the repo also the checkout local dir name
    name: str
    # The path to the local root directory that contains this git repo
    local_root_dir: Path
    # The root URL that contains the a Git repo with this name
    remote_root_url: str = None

    @property
    def local_repo_dir(self):
        return self.local_root_dir / self.name

    def remote_repo_url(self):
        return f"{self.remote_root_url}" + uritemplate.expand("{/name}", name=self.name)

    def is_real_git(self):
        """
        Return True if this local repo is initialized on disk, False if this is
        just some directory.
        """
        return (self.local_repo_dir / ".git").exists()

    def __post_init__(self):
        self.local_root_dir = Path(self.local_root_dir).resolve()

    def init(self):
        raise NotImplementedError()

    def clone(self):
        raise NotImplementedError()

    def pull(self):
        raise NotImplementedError()

    def push(self):
        raise NotImplementedError()


def build_direct_federation_config_file_url(
    remote_root_url: str,
    federation_name: str,
    config_filename: str,
):
    """
    Return the URL to download a remote config file for a federation
    """
    return build_raw_download_url(
        root_url=remote_root_url,
        repo=federation_name,
        path=config_filename,
        branch="main",
    )


def build_raw_download_url(
    root_url: str,
    repo: str,
    path: str,
    branch: str = "main",
    builder=None,
):
    """
    Return a direct access raw URL to a file in a know public repo.
    """
    _scheme, server, _path, _query, _fragment = urlsplit(root_url)
    if not builder:
        git_url_builder_by_server = {
            "github.com": build_raw_download_url_github,
            "gitlab.com": build_raw_download_url_gitlab,
            "codeberg.org": build_raw_download_url_codeberg,
        }
        builder = git_url_builder_by_server[server]

    return builder(root_url=root_url, repo=repo, path=path, branch=branch)


def build_raw_download_url_github(
    root_url: str,
    repo: str,
    path: str,
    branch: str = "main",
):
    """
    Return a direct access raw URL to a file in a github repo.
    """
    # NB: an alternative could be
    # https://raw.githubusercontent.com/{org}/{repo}/refs/heads/main/{path}
    return "/".join([root_url, repo, "raw/refs/heads", branch, path])


def build_raw_download_url_gitlab(
    root_url: str,
    repo: str,
    path: str,
    branch: str = "main",
):
    """
    Return a direct access raw URL to a file in a gitlab repo.
    """
    # note that the org can be multiple path segments
    return "/".join([root_url, repo, "-/raw", branch, path])


def build_raw_download_url_codeberg(
    root_url: str,
    repo: str,
    path: str,
    branch: str = "main",
):
    """
    Return a direct access raw URL to a file in a codeberg repo.
    """
    return "/".join([root_url, repo, "raw/branch", branch, path])


def compute_purl_hash(purl: Union[PackageURL, str], max_value: int = 1024) -> str:
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
    >>> compute_purl_hash("pkg:pypi/univers@30.12.0")
    '0145'
    >>> compute_purl_hash("pkg:pypi/univers@10.12.0")
    '0145'
    >>> compute_purl_hash("pkg:pypi/univers@30.12.0?foo=bar#sub/path")
    '0145'

    The hash is left padded with zeros::
    >>> compute_purl_hash("pkg:pypi/expressionss")
    '0760'

    We use the canonical PURL. Here pypi normalization always uses dash for
    underscore ::

    >>> compute_purl_hash("pkg:pypi/license_expression")
    '0297'
    >>> compute_purl_hash("pkg:pypi/license-expression")
    '0297'

    Originally designed in :
    https://github.com/aboutcode-org/purldb/pull/235/files#diff-a1fd023bd42d73f56019d540f38be711255403547add15108540d70f9948dd40R154
    """

    core_purl = get_core_purl(purl).to_string()
    return _compute_hash(core_purl=core_purl, max_value=max_value)


def _compute_hash(core_purl: str, max_value: int = 1024) -> str:
    """
    Return a hash string from a ``core_purl`` string. The core purl string
    must be computed ahead

    For example::

    >>> compute_purl_hash("pkg:pypi/univers")
    '0145'

    The hash is left padded with zeros::
    >>> compute_purl_hash("pkg:pypi/expressionss")
    '0760'
    """

    core_purl_bytes = core_purl.encode("utf-8")
    hash_bytes = sha256(core_purl_bytes).digest()
    # Only keep the first 4 bytes to avoid creating very large integers.
    # We only support up to 8192 hashes max_value, 2**13 , aka 13 bits.
    # So 2 bytes are enough.
    hash_bytes = hash_bytes[:2]
    # Convert bytes to integer, using little endian
    hash_int = int.from_bytes(hash_bytes, byteorder="little")
    # compute modulo max value
    short_int = hash_int % max_value
    # return as 4-char string left padded with 0
    return f"{short_int:04}"


def is_valid_power_of_two(n: int, max_value: int = 1024):
    """
    Return True if ``n`` is a power of two between 1 and ``max_value``.
    Use bit manipulations.

    See https://stackoverflow.com/questions/57025836
    """
    return n > 0 and n <= max_value and (n & (n - 1) == 0)


def percent_quote_more(qs):
    """
    Return a percent-quoted string from ``qs`` string by quoting all non-quoted
    characters, but ignoring already quoted characters. This makes the quoted
    string safe to use in a path as a directory or file name.

    For example::
    >>> percent_quote_more("foo")
    'foo'

    >>> percent_quote_more("foo/bar")
    'foo%2Fbar'

    >>> percent_quote_more("foo:bar")
    'foo%3Abar'

    >>> percent_quote_more("foo%2Fbar")
    'foo%2Fbar'
    """
    if not qs:
        return qs
    try:
        return quote(qs, safe="%")
    except Exception as e:
        raise Exception(f"Failed to percent_quote_more: {qs!r}") from e


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


def package_path_elements(
    purl: Union[PackageURL, str],
    max_value: int = 1024,
):
    """
    Return a 4-tuple of POSIX path strings from the ``purl`` string or object.

    The tuple members are:
        (short-purl-hash, core-purl-path, purl-version, purl-extra-path)

    These members can be joined as needed with a POSIX "/" path separator to
    create a repository and directory structures in a DataCluster.

    short-purl-hash: PURL-based hash, up to max_value
    core-purl-path: type/namespace/name
    purl-version: PURL version, further percent-quoted for safe path usage
    extra_path: qualifiers#subpath combined and percent-quoted for safe path usage

    For example:

    We use the same hash and base path for different versions of the same PURL::

    >>> package_path_elements("pkg:pypi/license_expression@30.3.1")
    ('0297', 'pypi/license-expression', '30.3.1', '')
    >>> package_path_elements("pkg:pypi/license_expression@10.3.1")
    ('0297', 'pypi/license-expression', '10.3.1', '')

    We percent-quote versions and qualifiers+subpath elements to make these safe
    to use as directory names in filesystems. We avoid double encoding of
    already quoted parts::

    >>> package_path_elements("pkg:pypi/license_expression@30.3.1?foo=bar&baz=bar#sub/path")
    ('0297', 'pypi/license-expression', '30.3.1', 'baz%3Dbar%26foo%3Dbar%23sub%2Fpath')

    The function accepts also a PURL object::

    >>> purl = PackageURL(
    ...     type="pypi",
    ...     name="license_expression",
    ...     version="b#ar/?30.3.2!",
    ...     qualifiers=dict(foo="bar"),
    ...     subpath="a/b/c")
    >>> package_path_elements(purl)
    ('0297', 'pypi/license-expression', 'b%23ar%2F%3F30.3.2%21', 'foo%3Dbar%23a%2Fb%2Fc')
    """
    purl = as_purl(purl)
    core_purl = get_core_purl(purl).to_string()

    # core path is kept encoded, just stripped from the pkg: prefix
    _pkg, _, core_path = core_purl.partition(":")
    purl_hash = _compute_hash(core_purl=core_purl, max_value=max_value)

    version = normalize_version(purl.version, purl.type)
    if version:
        version = percent_quote_more(version)

    extra_path = ""
    if pq := purl.qualifiers:
        # note that we percent-quote everything including the / character
        extra_path = percent_quote_more(normalize_qualifiers(pq, encode=True))

    if psp := purl.subpath:
        psp = normalize_subpath(psp, encode=True)
        extra_path += percent_quote_more(f"#{psp}")

    return purl_hash, core_path, version, extra_path
