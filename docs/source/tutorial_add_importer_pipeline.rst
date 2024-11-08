.. _tutorial_add_importer_pipeline:

Add a new pipeline to import advisories
========================================


TL;DR
-------

#. Create a new file ``{name}_importer.py`` inside **vulnerabilities/pipelines/**.
#. Create a new importer pipeline by inheriting **VulnerableCodeBaseImporterPipeline**
   defined in **vulnerabilities.pipelines**. By convention the importer pipeline
   class should end with **ImporterPipeline**.
#. Specify the license of upstream data being imported.
#. Implement the ``advisories_count`` and ``collect_advisories`` methods.
#. Add the newly created importer pipeline to the importers registry at
   **vulnerabilities/importers/__init__.py**


Pipeline
--------

We use `aboutcode.pipeline <https://github.com/aboutcode-org/scancode.io/tree/main/aboutcode/pipeline>`_
for importing and improving data. At a very high level, a working pipeline contains classmethod
``steps`` that defines what steps to run and in what order. These steps are essentially just
functions. Pipeline provides an easy and effective way to log events inside these steps (it
automatically handles rendering and dissemination for these logs.)

It also includes built-in progress indicator, which is essential since some of the jobs we run
in the pipeline are long-running tasks that require proper progress indicators. Pipeline provides
way to seamlessly records the progress (it automatically takes care of rendering and dissemination
of these progress).

Additionally, the pipeline offers a consistent structure, making it easy to run these pipeline steps
with message queue like RQ and store all events related to a particular pipeline for
debugging/improvements.

This tutorial contains all the things one should know to quickly implement an importer pipeline.
Many internal details about importer pipeline can be found inside the
`vulnerabilities/pipelines/__init__.py
<https://github.com/aboutcode-org/vulnerablecode/blob/main/vulnerabilities/pipelines/__init__.py>`_ file.


.. _tutorial_add_importer_pipeline_prerequisites:

Prerequisites
--------------

Before writing pipeline to import advisories, it is important to familiarize yourself with
the following concepts.

PackageURL
~~~~~~~~~~

VulnerableCode extensively uses Package URLs to identify a package. See the
`PackageURL specification <https://github.com/package-url/purl-spec>`_ and its `Python implementation
<https://github.com/package-url/packageurl-python>`_ for more details.

**Example usage:**

.. code:: python

    from packageurl import PackageURL
    purl = PackageURL(name="ffmpeg", type="deb", version="1.2.3")


AdvisoryData
~~~~~~~~~~~~~

``AdvisoryData`` is an intermediate data format:
it is expected that your importer will convert the raw scraped data into ``AdvisoryData`` objects.
All the fields in ``AdvisoryData`` dataclass are optional; it is the importer's responsibility to
ensure that it contains meaningful information about a vulnerability.

AffectedPackage
~~~~~~~~~~~~~~~

``AffectedPackage`` data type is used to store a range of affected versions and a fixed version of a
given package. For all version-related data, `univers <https://github.com/aboutcode-org/univers>`_ library
is used.

Univers
~~~~~~~

`univers <https://github.com/aboutcode-org/univers>`_ is a Python implementation of the `vers specification <https://github.com/package-url/purl-spec/pull/139>`_.
It can parse and compare all the package versions and all the ranges,
from debian, npm, pypi, ruby and more.
It processes all the version range specs and expressions.


Writing an Importer Pipeline
-----------------------------


Create file for the new importer pipeline
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

All pipelines, including the importer pipeline, are located in the
`vulnerabilities/pipelines/
<https://github.com/aboutcode-org/vulnerablecode/tree/main/vulnerabilities/pipelines>`_ directory.

The importer pipeline is implemented by subclassing **VulnerableCodeBaseImporterPipeline**
and implementing the unimplemented methods. Since most tasks, such as inserting **AdvisoryData**
into the database and creating package-vulnerability relationships, are the same regardless of
the source of the advisory, these tasks are already taken care of in the base importer pipeline,
i.e., **VulnerableCodeBaseImporterPipeline**. You can simply focus on collecting the raw data and
parsing it to create proper **AdvisoryData** objects.


Specify the importer license
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The pipeline scrape data off the internet.  In order to make sure the data is useable, a license
must be provided.

Populate the ``spdx_license_expression`` with the appropriate value. The SPDX license identifiers
can be found at `ScanCode LicenseDB <https://scancode-licensedb.aboutcode.org/>`_.

.. note::
   An SPDX license identifier by itself is a valid license expression. In case you need more
   complex expressions, see https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/


Implement the ``advisories_count`` method
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``advisories_count`` method returns the total number of advisories that will be collected by
this pipeline.

Suppose the upstream data is a single JSON file containing a list of security advisories;
in that case, you can simply return the count of security advisories in the JSON file,
and that's it.

.. note::
    In some cases, it could be difficult to get the exact total number of advisories that would
    be collected without actually processing the advisories. In such case returning the best
    estimate will also work.

    **advisories_count** is used to enable a proper progress indicator and is not used beyond that.
    If it is impossible (a super rare case) to compute the total advisory count beforehand,
    just return ``0``.


Implement the ``collect_advisories`` method
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``collect_advisories`` method collects and parses the advisories from the data source and
yield an *AdvisoryData*.

At this point, an example importer will look like this:

.. code-block:: python
    :caption: vulnerabilities/pipelines/example_importer.py
    :linenos:
    :emphasize-lines: 16-17, 20-21, 23-24

    from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipeline

    class ExampleImporterPipeline(VulnerableCodeBaseImporterPipeline):
        """Collect advisories Example."""

        pipeline_id = "example_importer"

        root_url = "https://example.org/path/to/advisories/"
        license_url = "https://exmaple.org/license/"
        spdx_license_expression = "CC-BY-4.0"
        importer_name = "Example Importer"

        @classmethod
        def steps(cls):
            return (
                cls.collect_and_store_advisories,
                cls.import_new_advisories,
            )

        def advisories_count(self) -> int:
            raise NotImplementedError

        def collect_advisories(self) -> Iterable[AdvisoryData]:
            raise NotImplementedError


This pipeline is only a valid skeleton and does not import anything at all.

Let us implement a working pipeline that actually imports some data.

Here we have a ``dummy_package`` which follows ``NginxVersionRange`` and ``SemverVersion`` for
version management from `univers <https://github.com/aboutcode-org/univers>`_.

.. note::

   It is possible that the versioning scheme you are targeting has not yet been
   implemented in the `univers <https://github.com/aboutcode-org/univers>`_ library.
   If this is the case, you will need to head over there and implement one.

.. code-block:: python
    :caption: vulnerabilities/pipelines/example_importer.py
    :linenos:
    :emphasize-lines: 34-35, 37-40

    from datetime import datetime
    from datetime import timezone
    from typing import Iterable

    from packageurl import PackageURL
    from univers.version_range import NginxVersionRange
    from univers.versions import SemverVersion

    from vulnerabilities.importer import AdvisoryData
    from vulnerabilities.importer import AffectedPackage
    from vulnerabilities.importer import Reference
    from vulnerabilities.importer import VulnerabilitySeverity
    from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipeline
    from vulnerabilities.severity_systems import SCORING_SYSTEMS


    class ExampleImporterPipeline(VulnerableCodeBaseImporterPipeline):
        """Collect advisories Example."""

        pipeline_id = "example_importer"

        root_url = "https://example.org/path/to/advisories/"
        license_url = "https://example.org/license/"
        spdx_license_expression = "CC-BY-4.0"
        importer_name = "Example Importer"

        @classmethod
        def steps(cls):
            return (
                cls.collect_and_store_advisories,
                cls.import_new_advisories,
            )

        def advisories_count(self) -> int:
            return len(fetch_advisory_data())

        def collect_advisories(self) -> Iterable[AdvisoryData]:
            raw_data = fetch_advisory_data()
            for data in raw_data:
                yield parse_advisory_data(data)


    def fetch_advisory_data():
        return [
            {
                "id": "CVE-2021-23017",
                "summary": "1-byte memory overwrite in resolver",
                "advisory_severity": "medium",
                "vulnerable": "0.6.18-1.20.0",
                "fixed": "1.20.1",
                "reference": "http://mailman.nginx.org/pipermail/nginx-announce/2021/000300.html",
                "published_on": "14-02-2021 UTC",
            },
            {
                "id": "CVE-2021-1234",
                "summary": "Dummy advisory",
                "advisory_severity": "high",
                "vulnerable": "0.6.18-1.20.0",
                "fixed": "1.20.1",
                "reference": "http://example.org/cve-2021-1234",
                "published_on": "06-10-2021 UTC",
            },
        ]


    def parse_advisory_data(raw_data) -> AdvisoryData:
        purl = PackageURL(type="example", name="dummy_package")
        affected_version_range = NginxVersionRange.from_native(raw_data["vulnerable"])
        fixed_version = SemverVersion(raw_data["fixed"])
        affected_package = AffectedPackage(
            package=purl, affected_version_range=affected_version_range, fixed_version=fixed_version
        )
        severity = VulnerabilitySeverity(
            system=SCORING_SYSTEMS["generic_textual"], value=raw_data["advisory_severity"]
        )
        references = [Reference(url=raw_data["reference"], severities=[severity])]
        date_published = datetime.strptime(raw_data["published_on"], "%d-%m-%Y %Z").replace(
            tzinfo=timezone.utc
        )
        advisory_url = f"https://example.org/advisory/{raw_data['id']}"

        return AdvisoryData(
            aliases=[raw_data["id"]],
            summary=raw_data["summary"],
            affected_packages=[affected_package],
            references=references,
            url=advisory_url,
            date_published=date_published,
        )


.. important::
    Steps should include ``collect_and_store_advisories`` and ``import_new_advisories``
    in the order shown above. They are defined in **VulnerableCodeBaseImporterPipeline**.

    It is the **collect_and_store_advisories** that is responsible for making calls to
    **collect_advisories** and **advisories_count**, and hence **collect_advisories** and
    **advisories_count** should never be directly added in steps.


.. attention::

   Implement ``on_failure`` to handle cleanup in case of pipeline failure.
   Cleanup of downloaded archives or cloned repos is necessary to avoid potential resource leakage.

.. note::

   | Use ``make valid`` to format your new code using black and isort automatically.
   | Use ``make check`` to check for formatting errors.

Register the Importer Pipeline
------------------------------

Finally, register your pipeline in the importer registry at
`vulnerabilities/importers/__init__.py
<https://github.com/aboutcode-org/vulnerablecode/blob/main/vulnerabilities/importers/__init__.py>`_

.. code-block:: python
    :caption: vulnerabilities/importers/__init__.py
    :linenos:
    :emphasize-lines: 1, 6

    from vulnerabilities.pipelines import example_importer
    from vulnerabilities.pipelines import nginx_importer

    IMPORTERS_REGISTRY = [
        nginx_importer.NginxImporterPipeline,
        example_importer.ExampleImporterPipeline,
        ]

    IMPORTERS_REGISTRY = {
        x.pipeline_id if issubclass(x, VulnerableCodeBaseImporterPipeline) else x.qualified_name: x
        for x in IMPORTERS_REGISTRY
    }

Congratulations! You have written your first importer pipeline.

Run Your First Importer Pipeline
--------------------------------

If everything went well, you will see your pipeline in the list of available importers.

.. code-block:: console
   :emphasize-lines: 5

    $ ./manage.py import --list

    Vulnerability data can be imported from the following importers:
    nginx_importer
    example_importer

Now, run the importer.

.. code-block:: console

    $ ./manage.py import example_importer

    Importing data using example_importer
    INFO 2024-10-16 10:15:10.483 Pipeline [ExampleImporterPipeline] starting
    INFO 2024-10-16 10:15:10.483 Step [collect_and_store_advisories] starting
    INFO 2024-10-16 10:15:10.483 Collecting 2 advisories
    INFO 2024-10-16 10:15:10.498 Successfully collected 2 advisories
    INFO 2024-10-16 10:15:10.498 Step [collect_and_store_advisories] completed in 0 seconds
    INFO 2024-10-16 10:15:10.498 Step [import_new_advisories] starting
    INFO 2024-10-16 10:15:10.499 Importing 2 new advisories
    INFO 2024-10-16 10:15:10.562 Successfully imported 2 new advisories
    INFO 2024-10-16 10:15:10.563 Step [import_new_advisories] completed in 0 seconds
    INFO 2024-10-16 10:15:10.563 Pipeline completed in 0 seconds


See :ref:`command_line_interface` for command line usage instructions.
