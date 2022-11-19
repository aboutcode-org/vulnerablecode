.. _tutorial_add_a_new_importer:

Add a new importer
====================

This tutorial contains all the things one should know to quickly implement an importer.
Many internal details about importers can be found inside the
:file:`vulnerabilites/importer.py` file.
Make sure to go through :ref:`importer-overview` before you begin writing one.

TL;DR
-------

#. Create a new :file:`vulnerabilities/importers/{importer_name.py}` file.
#. Create a new importer subclass inheriting from the ``Importer`` superclass defined in
   ``vulnerabilites.importer``. It is conventional to end an importer name with *Importer*.
#. Specify the importer license.
#. Implement the ``advisory_data`` method to process the data source you are
   writing an importer for.
#. Add the newly created importer to the importers registry at
   ``vulnerabilites/importers/__init__.py``

.. _tutorial_add_a_new_importer_prerequisites:

Prerequisites
--------------

Before writing an importer, it is important to familiarize yourself with the following concepts.

PackageURL
^^^^^^^^^^^^

VulnerableCode extensively uses Package URLs to identify a package. See the
`PackageURL specification <https://github.com/package-url/purl-spec>`_ and its `Python implementation
<https://github.com/package-url/packageurl-python>`_ for more details.

**Example usage:**

.. code:: python

    from packageurl import PackageURL
    purl = PackageURL(name="ffmpeg", type="deb", version="1.2.3")


AdvisoryData
^^^^^^^^^^^^^

``AdvisoryData`` is an intermediate data format:
it is expected that your importer will convert the raw scraped data into ``AdvisoryData`` objects.
All the fields in ``AdvisoryData`` dataclass are optional; it is the importer's resposibility to
ensure that it contains meaningful information about a vulnerability.

AffectedPackage
^^^^^^^^^^^^^^^^

``AffectedPackage`` data type is used to store a range of affected versions and a fixed version of a
given package. For all version-related data, `univers <https://github.com/nexB/univers>`_ library
is used.

Univers
^^^^^^^^

`univers <https://github.com/nexB/univers>`_ is a Python implementation of the `vers specification <https://github.com/package-url/purl-spec/pull/139>`_.
It can parse and compare all the package versions and all the ranges,
from debian, npm, pypi, ruby and more.
It processes all the version range specs and expressions.

Importer
^^^^^^^^^

All the generic importers need to implement the ``Importer`` class.
For ``Git`` or ``Oval`` data source, ``GitImporter`` or ``OvalImporter`` could be implemented.

.. note::

   ``GitImporter`` and ``OvalImporter`` need a complete rewrite.
   Interested in :ref:`contributing` ?

Writing an importer
---------------------

Create Importer Source File
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

All importers are located in the :file:`vulnerabilites/importers` package.
Create a new file to put your importer code in.
Generic importers are implemented by writing a subclass for the ``Importer`` superclass and
implementing the unimplemented methods.

Specify the Importer License
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Importers scrape data off the internet.  In order to make sure the data is useable, a license
must be provided.
Populate the ``spdx_license_expression`` with the appropriate value.
The SPDX license identifiers can be found at https://spdx.org/licenses/.

.. note::
   An SPDX license identifier by itself is a valid licence expression. In case you need more complex
   expressions, see https://spdx.github.io/spdx-spec/SPDX-license-expressions/

Implement the ``advisory_data`` Method
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``advisory_data`` method scrapes the advisories from the data source this importer is
targeted at.
It is required to return an *Iterable of AdvisoryData objects*, and thus it is a good idea to yield
from this method after creating each AdvisoryData object.

At this point, an example importer will look like this:

:file:`vulnerabilites/importers/example.py`

.. code-block:: python

    from typing import Iterable

    from packageurl import PackageURL

    from vulnerabilities.importer import AdvisoryData
    from vulnerabilities.importer import Importer


    class ExampleImporter(Importer):

        spdx_license_expression = "BSD-2-Clause"

        def advisory_data(self) -> Iterable[AdvisoryData]:
            return []

This importer is only a valid skeleton and does not import anything at all.

Let us implement another dummy importer that actually imports some data.

Here we have a ``dummy_package`` which follows ``NginxVersionRange`` and ``SemverVersion`` for
version management from `univers <https://github.com/nexB/univers>`_.

.. note::

   It is possible that the versioning scheme you are targetting has not yet been
   implemented in the `univers <https://github.com/nexB/univers>`_ library.
   If this is the case, you will need to head over there and implement one.

.. code-block:: python

    from datetime import datetime
    from datetime import timezone
    from typing import Iterable

    import requests
    from packageurl import PackageURL
    from univers.version_range import NginxVersionRange
    from univers.versions import SemverVersion

    from vulnerabilities.importer import AdvisoryData
    from vulnerabilities.importer import AffectedPackage
    from vulnerabilities.importer import Importer
    from vulnerabilities.importer import Reference
    from vulnerabilities.importer import VulnerabilitySeverity
    from vulnerabilities.severity_systems import SCORING_SYSTEMS


    class ExampleImporter(Importer):

        spdx_license_expression = "BSD-2-Clause"

        def advisory_data(self) -> Iterable[AdvisoryData]:
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
                "reference": "http://example.com/cve-2021-1234",
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

        return AdvisoryData(
            aliases=[raw_data["id"]],
            summary=raw_data["summary"],
            affected_packages=[affected_package],
            references=references,
            date_published=date_published,
        )


.. note::

   | Use ``make valid`` to format your new code using black and isort automatically.
   | Use ``make check`` to check for formatting errrors.

Register the Importer
^^^^^^^^^^^^^^^^^^^^^^

Finally, register your importer in the importer registry at
:file:`vulnerabilites/importers/__init__.py`

.. code-block:: python
   :emphasize-lines: 1, 4

    from vulnerabilities.importers import example
    from vulnerabilities.importers import nginx

    IMPORTERS_REGISTRY = [nginx.NginxImporter, example.ExampleImporter]

    IMPORTERS_REGISTRY = {x.qualified_name: x for x in IMPORTERS_REGISTRY}

Congratulations! You have written your first importer.

Run Your First Importer
^^^^^^^^^^^^^^^^^^^^^^^^^^

If everything went well, you will see your importer in the list of available importers.

.. code-block:: console
   :emphasize-lines: 5

    $ ./manage.py import --list

    Vulnerability data can be imported from the following importers:
    vulnerabilities.importers.nginx.NginxImporter
    vulnerabilities.importers.example.ExampleImporter

Now, run the importer.

.. code-block:: console

    $ ./manage.py import vulnerabilities.importers.example.ExampleImporter

    Importing data using vulnerabilities.importers.example.ExampleImporter
    Successfully imported data using vulnerabilities.importers.example.ExampleImporter

See :ref:`command_line_interface` for command line usage instructions.

Enable Debug Logging (Optional)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For more visibility, turn on debug logs in :file:`vulnerablecode/settings.py`.

.. code-block:: python

    DEBUG = True
    LOGGING = {
        'version': 1,
        'disable_existing_loggers': False,
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
            },
        },
        'root': {
            'handlers': ['console'],
            'level': 'DEBUG',
        },
    }

Invoke the import command now and you will see (in a fresh database):

.. code-block:: console

    $ ./manage.py import vulnerabilities.importers.example.ExampleImporter

    Importing data using vulnerabilities.importers.example.ExampleImporter
    Starting import for vulnerabilities.importers.example.ExampleImporter
    [*] New Advisory with aliases: ['CVE-2021-23017'], created_by: vulnerabilities.importers.example.ExampleImporter
    [*] New Advisory with aliases: ['CVE-2021-1234'], created_by: vulnerabilities.importers.example.ExampleImporter
    Finished import for vulnerabilities.importers.example.ExampleImporter. Imported 2 advisories.
    Successfully imported data using vulnerabilities.importers.example.ExampleImporter
