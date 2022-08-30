.. _importer-overview:

Importer Overview
==================

Importers are responsible for scraping vulnerability data such as vulnerabilities and their fixes and
for storing the scraped information in a structured fashion. The structured data created by the
importer then provides input to an improver (see :ref:`improver-overview`), which is responsible
for creating a relational model for vulnerabilities, affected packages and fixed packages.

All importer implementation-related code is defined in :file:`vulnerabilites/importer.py`.

In addition, the framework-related code for actually invoking and processing the importers is
located in :file:`vulnerabilites/import_runner.py`.

The importers, after scraping, provide ``AdvisoryData`` objects. These objects are then
processed and inserted into the ``Advisory`` model.

While implementing an importer, it is important to make sure that the importer does not alter the
upstream data at all. Its only job is to convert the data from a data source into structured -- yet
non-relational -- data.  This ensures that we always have a *true* copy of an advisory without any
modifications.

Given that a lot of advisories publish version ranges of affected
packages, it is necessary to store those ranges in a structured manner. *Vers* was designed to
solve this problem. It has been implemented in the `univers <https://github.com/nexB/univers>`_
library whose development goes hand in hand with VulnerableCode.

The data imported by importers is not useful by itself: it must be processed into a relational
model. The version ranges are required to be resolved into concrete ranges. These are achieved by
``Improvers`` (see :ref:`improver-overview` for details).

As of now, the following importers have been implemented in VulnerableCode:

.. include:: ../../SOURCES.rst
