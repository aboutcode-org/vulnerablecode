aboutcode.federated
===================

This is a library of utilities to compute ids and file paths for AboutCode
federated data based on Package URL


Federated data utilities goal is to handle content-defined and hash-addressable
Package data keyed by PURL stored in many Git repositories. This approach to
federate decentralized data is called FederatedCode.


Overview
========

The main design elements for these utilities are:

1. **Data Federation**: A Data Federation is a database, representing a consistent,
non-overlapping set of data kind clusters (like scans, vulnerabilities or SBOMs)
across many package ecosystems, aka. PURL types.
A Federation is similar to a traditional database.

2. **Data Cluster**: A Data Federation contains Data Clusters, where a Data Cluster
purpose is to store the data of a single kind (like scans) across multiple PURL
types. The cluster name is the data kind name and is used as the prefix for
repository names. A Data Cluster is akin to a table in a traditional database.

3. **Data Repository**: A DataCluster contains of one or more Git Data Repository,
each storing datafiles of the cluster data kind and a one PURL type, spreading
the datafiles in multiple Data Directories. The name is data-kind +PURL-
type+hashid. A Repository is similar to a shard or tablespace in a traditional
database.

4. **Data Directory**: In a Repository, a Data Directory contains the datafiles for
PURLs. The directory name PURL-type+hashid

5. **Data File**: This is a Data File of the DataCluster's Data Kind that is
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



License
-------

Copyright (c) AboutCode and others. All rights reserved.

SPDX-License-Identifier: Apache-2.0

See https://github.com/aboutcode-org/vulnerablecode for support or download.

See https://aboutcode.org for more information about AboutCode OSS projects.
