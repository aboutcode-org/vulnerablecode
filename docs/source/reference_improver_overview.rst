.. _improver-overview:

Improver Overview
===================

Improvers improve upon already imported data. They are responsible for creating a relational
model for vulnerabilites and packages.

An Improver is supposed to contain data points about a vulnerability and the relevant discrete
affected and fixed packages (in the form of `PackageURLs
<https://github.com/package-url/packageurl-python>`_).
There is no notion of version ranges here, all package versions must be explicitly specified.
As this concrete relationship might not always be absolutely correct, improvers supply with a
confidence score and only the record with the highest confidence against a vulnerability and package
relationship is stored in the database.

There are two categories of improvers:

- **Generic**: Improve upon some imported data irrespective of any importer. These improvers are
  defined in :file:`vulnerabilites/improvers/`
- **Importer Specific**: Improve upon data imported by a specific importer. These are defined in the
  corresponding importer file itself.

Both types of improvers internally work in a similar fashion. They indicate which ``Advisory`` they
are interested in and when supplied with those Advisories, they return Inferences.
An ``Inference`` is more explicit than an ``Advisory`` and is able to answer the questions like, "Is
package A vulnerable to Vulnerability B ?". Of course, there is some confidence attached with the
answer which could also be ``MAX_CONFIDENCE`` in certain cases.

The possibilities with improvers is endless, they are not restricted to take one approach. Features
like *Time Travel* and *finding fix commits* could be Implemented as well.

You can find more in-code documentation about improvers in :file:`vulnerabilites/improver.py` and
the framework responsible for invoking these improvers in :file:`vulnerabilites/improve_runner.py`
