.. _importer-overview:

Importer Overview
==================

Importers are responsible for scraping advisories data such as advisories and their fixes
and for storing the scraped information in a structured fashion. The structured data created by the
importer then provides input to an improver (see :ref:`improver-overview`), which is responsible
for creating a relational model for advisories, affected packages and fixed packages.

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

Incremental GitHub OSV imports
-----------------------------------

The ``github_osv_importer_v2`` pipeline uses a database ``GitImportCheckpoint`` keyed by
pipeline ID and repository URL to remember its last successfully imported Git commit.
The first run imports all JSON files in ``advisories/github-reviewed``. Later runs compare
the checkpoint and current clone's HEAD with ``git diff --name-status`` and import only
added or changed advisory JSON files. Unchanged files are not parsed or written again.
Renames are treated as deletion plus addition, so the destination file is imported.

If the previous commit is unavailable, including when a shallow clone omits it, or is no
longer an ancestor of HEAD, the pipeline falls back to a full import. A run with no changed
advisory files imports nothing. The existing cloning mechanism is retained; this prototype
reduces parsing and database work rather than clone transfer size.

The proposed deletion policy is to log deleted upstream paths for review and retain their
stored advisories and history. A deleted file does not by itself establish that an advisory
should be withdrawn. This also applies to a run containing only deletions.

The checkpoint is saved as the final step, after all selected advisories have been imported
and the temporary clone has been removed. Clone, parsing, storage, and cleanup failures
leave the checkpoint unchanged. This importer opts into stopping on an individual storage
failure; other importers keep their existing behavior. A retry reprocesses the delta, and
already imported advisory content is deduplicated by the existing import mechanism.

To force a full import, remove this pipeline and repository's ``GitImportCheckpoint`` row
before the next run. Apply the database migration before running the updated importer.
This prototype is limited to GitHub OSV. Maintainers should agree on the deletion policy
and checkpoint timing before applying the approach to other pipelines.
