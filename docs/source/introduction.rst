.. _introduction:

VulnerableCode Overview
========================

VulnerableCode is a work-in-progress towards a free and open vulnerabilities
database and the packages they impact and the tools to aggregate and correlate
these vulnerabilities.

Why VulnerableCode?
-------------------

The existing solutions are commercial proprietary vulnerability databases, which
in itself does not make sense because the data is about FOSS (Free and Open
Source Software).

The National Vulnerability Database which is a primary centralized data source
for known vulnerabilities is not particularly well suited to address FOSS
security issues because:

1. It predates the explosion of FOSS software usage
2. It's data format reflects a commercial vendor-centric point of view in part
   due to the usage of `CPE <https://nvd.nist.gov/products/cpe>`__ to map
   vulnerabilities to existing packages.
3. CPEs are just not designed to map FOSS to vulnerabilities owing to their
   vendor-product centric semantics. This makes it really hard to answer the
   fundamental questions "Is package foo vulnerable" and "Is package foo
   vulnerable to vulnerability bar?"

How does it work?
-----------------

VulnerableCode independently aggregates many software vulnerability data sources
and supports data re-creation in a decentralized fashion. These data sources
(see complete list :ref:`here <importers_link>`) include security advisories
published by Linux and BSD distributions, application software package managers
and package repositories, FOSS projects, GitHub and more. Thanks to this
approach, the data is focused on specific ecosystems yet aggregated in a single
database that enables querying a richer graph of relations between multiple
incarnations of a package. Being specific increases the accuracy and validity
of the data as the same version of an upstream package across different
ecosystems may or may not be vulnerable to the same vulnerability.

The packages are identified using Package URL `PURL
<https://github.com/package-url/purl-spec>`__ as primary identifiers rather than
CPEs. This makes answers to questions such as "Is package foo vulnerable
to vulnerability bar?"  much more accurate and easy to interpret.


The primary access to the data is through a REST API.

In addition, an emerging web interface goal is to support vulnerabilities data
browsing and search and progressively to enable community curation of the data
with the addition of new packages and vulnerabilities, and reviewing and
updating their relationships.

We also plan to mine for vulnerabilities which didn't receive any
exposure due to various reasons like but not limited to the complicated
procedure to receive CVE ID or not able to classify a bug as a security
compromise.


Is VulnerableCode being actively developed?
-------------------------------------------

Yes -- VulnerableCode is a work in progress! Please stay in touch on our `Gitter channel <https://gitter.im/aboutcode-org/vulnerablecode>`_; and if you have any feedback, feel free to `enter an issue in our GitHub repo <https://github.com/nexB/vulnerablecode/issues>`_.


Recent presentations
--------------------

- `Open Source Summit 2020 <https://github.com/nexB/vulnerablecode/blob/main/docs/Presentations/Why-Is-There-No-Free-Software-Vulnerability-Database-v1.0.pdf>`_

.. Some of this documentation is borrowed from the metaflow documentation and is also
   under Apache-2.0
.. Copyright (c) Netflix
