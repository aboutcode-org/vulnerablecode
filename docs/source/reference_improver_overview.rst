.. _improver-overview:

Improver Overview
===================

Improvers improve upon already imported data. They are responsible for creating a relational
model for vulnerability advisories and packages.

An Improver is intended to contain data points about a advisory and the relevant discrete
affected and fixed packages (in the form of `PackageURLs
<https://github.com/package-url/packageurl-python>`_).
There is no notion of version ranges here; all package versions must be explicitly specified.
As this concrete relationship might not always be absolutely correct, improvers supply a
confidence score and only the record with the highest confidence against a vulnerability and package
relationship is stored in the database.

There are two categories of improvers:

- **Generic**: Improve upon some imported data irrespective of any importer. These improvers are
  defined in :file:`vulnerabilites/improvers/`.
- **Importer Specific**: Improve upon data imported by a specific importer. These are defined in the
  corresponding importer file itself.

Both types of improvers internally work in a similar fashion. They indicate which ``Advisory`` they
are interested in and when supplied with those Advisories, they return Inferences.
An ``Inference`` is more explicit than an ``Advisory`` and is able to answer questions like "Is
package A vulnerable to Vulnerability B ?". Of course, there is some confidence attached to the
answer, which could also be ``MAX_CONFIDENCE`` in certain cases.

The possibilities with improvers are endless; they are not restricted to take one approach. Features
like *Time Travel* and *finding fix commits* could be implemented as well.

You can find more in-code documentation about improvers in :file:`vulnerabilites/improver.py` and
the framework responsible for invoking these improvers in :file:`vulnerabilites/improve_runner.py`.

Advisory commit branch reachability
-----------------------------------

The ``collect_ref_fix_commits_v2`` pipeline collects commit references and then checks all
``PackageCommitPatch`` records, including commits collected directly by importers. Commits
and their advisory links are retained regardless of the check's result.

The ``PackageCommitPatch.branch_reachability`` field records one of three outcomes:

- ``reachable``: the commit is reachable from a branch in the referenced repository.
- ``unreachable``: a complete snapshot of all branch histories does not contain the commit.
  A commit reachable only from a tag, a detached HEAD, or a pull request ref does not count
  as belonging to a repository branch.
- ``unknown``: the commit has not been checked, the repository could not be cloned, or the
  clone has incomplete history. Shallow and partial clones cannot establish unreachability.

The check creates one temporary full bare clone per repository per run and removes it after
use. Clones include all branches and have a five-minute timeout; large repositories may
therefore remain unknown. A successful walk of all branch histories can establish
unreachability even when the referenced commit object is absent from the clone.

The advisory's commit details page displays the result and highlights unreachable commits.
Pipeline logs include the repository URL and hash for these commits, for upstream review.
These results describe the branches observed during the last check and may change when
branches are added, deleted, or rewritten. Rerunning the pipeline refreshes existing records;
a failed check sets their status to unknown. The flag is local enrichment and is not part of
the source advisory's serialized patch data.
