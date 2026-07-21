.. _advisory_todos:

Advisory Todos
==============

Overview
--------

The Advisory To-Dos queue contains security advisories that require
manual review to improve the quality and accuracy of VulnerableCode
data.

Supported Advisory Curation Types
---------------------------------

Our advisory curation process supports enriching and validating the
following vulnerability advisory metadata, depending on the information
available from trusted sources:

* **Package Curation**: See :ref:`advisory-package-curation`.

  - Advisories with conflicting **fixed** package versions.
  - Advisories with conflicting **affected** package versions.
  - Advisories with conflicting **affected** and **fixed** package
    versions.
  - *(Not currently supported)* Advisories missing affected package
    versions.
  - *(Not currently supported)* Advisories missing fixed package
    versions.
  - *(Not currently supported)* Advisories missing both affected and
    fixed package versions.

* **Severity Curation**: Advisories with conflicting CVSS vectors
  (CVSSv3, CVSSv3.1, and CVSSv4). See
  :ref:`advisory-severity-curation`.

* **Weakness Curation**: Advisories with conflicting Common Weakness
  Enumeration (CWE) identifiers. See
  :ref:`advisory-weakness-curation`.

* **Summary Curation**: *(Not currently supported).*

Each curation guide provides detailed instructions for reviewing
advisories in the corresponding curation queue.

Accessing the Advisory To-Dos Queue
-----------------------------------

1. Go to `public.vulnerablecode.io
   <https://public.vulnerablecode.io/>`_.

2. Click **Advisory To-Dos**.

   .. image:: images/advisory-to-dos-click.png

3. Click **Continue**.

   .. image:: images/continue-button.png

4. Search for advisories by **Alias**, or filter the list by
   **Resolved status** or **Issue type**.

   .. image:: images/advisory-to-do-dashbaord.png
