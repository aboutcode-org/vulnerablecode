.. _importer-overview:

Importer Overview
==================

Importers are responsible to scrape vulnerability data from various data sources without creating
a complete relational model between vulnerabilites, their fixes and store them in a structured
fashion.

All importer implementation related code is defined in :file:`vulnerabilites/importer.py`.

Whereas, the framework related code for actually invoking and processing the importers are
situated in :file:`vulnerabilites/import_runner.py`.

The importers, after scraping, provide with ``AdvisoryData`` objects. These objects are then
processed and inserted into the ``Advisory`` model.

While implementing an importer, it is important to make sure that the importer does not alter the
upstream data at all. Its only job is to convert the data from a data source into structured - yet
non relational - data. The importers must **not** be smart or performing trickeries
under the hood.
This ensures that we always have a *true* copy of an advisory without any speculations or
improvements.

As importers do not speculate and given that a lot of advisories publish version ranges of affected
packages, it is necessary to store those ranges in a structured manner. *Vers* was designed to
solve this problem. It has been implemented in the `univers <https://github.com/nexB/univers>`_
library whose development goes hand in hand with VulnerableCode.

The data imported by importers is not useful by itself, it must be processed into a relational
model. The version ranges are required to be dissolved into concrete ranges. These are achieved by
``Improvers``. For more, see: :ref:`improver-overview`

As of now, the following importers have been implemented in VulnerableCode

.. include:: ../../SOURCES.rst
