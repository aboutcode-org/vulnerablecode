.. _introduction:

VulnerableCode Overview
========================

VulnerableCode is a FOSS project that provides tools to build a database
of software vulnerabilities and the packages they impact. The tools
handle collecting, aggregating and correlating these vulnerabilities.
Our project also supports a public Cloud instance of this database –
VulnerableCode.io.

Why VulnerableCode?
-------------------

Existing vulnerability database solutions are primarily commercial or
proprietary which does not make sense because the data is about FOSS
(Free and Open Source Software).

The National Vulnerability Database, which is a primary centralized data
source for known vulnerabilities, is not particularly well suited to
address FOSS security issues because:

1. It predates the explosion of FOSS software usage
2. Its data format reflects a commercial vendor-centric point of view in part
   due to the usage of `CPE <https://nvd.nist.gov/products/cpe>`__ to map
   vulnerabilities to existing packages.
3. CPEs are not designed to map FOSS to vulnerabilities owing to their
   vendor-product centric semantics. This makes it really hard to answer the
   fundamental questions "Is package foo vulnerable" and "Is package foo
   vulnerable to vulnerability bar?"

How does it work?
-----------------

VulnerableCode independently aggregates many software vulnerability data sources
and supports data re-creation in a decentralized fashion. These data sources
(see complete list
`here <https://vulnerablecode.readthedocs.io/en/latest/importers_link.html#importers-link>`__)
include security advisories published by Linux and BSD distributions,
application software package managers and package repositories, FOSS projects,
GitHub and more. Thanks to this approach, the data is focused on specific ecosystems and
aggregated in a single database that enables querying a richer graph of relations between multiple
representations of a package. Being specific increases the accuracy and validity
of the data as the same version of an upstream package across different
ecosystems may or may not be subject to the same vulnerability.

In VulnerableCode, packages are identified using Package URL `PURL
<https://github.com/package-url/purl-spec>`__ as the primary identifier instead of
a CPE. This makes answers to questions such as "Is package foo vulnerable
to vulnerability bar?" more accurate and easier to interpret.

The primary access to VulnerableCode data is through a REST API, but there
is also a Web UI for searching and browsing vulnerabilities by package
or by vulnerability. For the initial releases both access modes are
read-only, but our longer-term goal is to enable community curation of
the data including addition of new packages and vulnerabilities, and
reviewing and updating their relationships.

*We also plan to mine for vulnerabilities that didn't receive any
exposure due to various reasons like, but not limited to, the complicated
procedure to obtain a CVE ID or not being able to classify a bug as a vulnerability.*


How can I contribute to VulnerableCode?
---------------------------------------

Please get in touch on our `Gitter channel <https://gitter.im/aboutcode-org/vulnerablecode>`__.
You can review or get the code and report issues at our `GitHub repo <https://github.com/nexB/vulnerablecode/issues>`__.

.. Some of this documentation is borrowed from the metaflow documentation and is also
   under Apache-2.0
.. Copyright (c) Netflix
