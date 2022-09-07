.. _tutorial_add_a_new_improver:

Add a new improver
====================

This tutorial contains all the things one should know to quickly
implement an improver.
Many internal details about improvers can be found inside the
:file:`vulnerabilites/improver.py` file.
Make sure to go through :ref:`improver-overview` before you begin writing one.

TL;DR
-------

#. Locate the importer that this improver will be improving data of at
   :file:`vulnerabilities/importers/{importer_name.py}` file.
#. Create a new improver subclass inheriting from the ``Improver`` superclass defined in
   ``vulnerabilites.improver``. It is conventional to end an improver name with *Improver*.
#. Implement the ``interesting_advisories`` property to return a QuerySet of imported data
   (``Advisory``) you are interested in.
#. Implement the ``get_inferences`` method to return an iterable of ``Inference`` objects for the
   given ``AdvisoryData``.
#. Add the newly created improver to the improvers registry at
   ``vulnerabilites/improvers/__init__.py``.

Prerequisites
--------------

Before writing an improver, it is important to familiarize yourself with the following concepts.

Importer
^^^^^^^^^^

Importers are responsible for scraping vulnerability data from various data sources without creating
a complete relational model between vulnerabilites and their fixes and storing them in a structured
fashion. These data are stored in the ``Advisory`` model and can be converted to an equivalent
``AdvisoryData`` for various use cases.
See :ref:`importer-overview` for a brief overview on importers.

Importer Prerequisites
^^^^^^^^^^^^^^^^^^^^^^^

Improvers consume data produced by importers, and thus it is important to familiarize yourself with
:ref:`Importer Prerequisites <tutorial_add_a_new_importer_prerequisites>`.

Inference
^^^^^^^^^^^

Inferences express the contract between the improvers and the improve runner framework.
An inference is intended to contain data points about a vulnerability without any uncertainties,
which means that one inference will target one vulnerability with the specific relevant affected and
fixed packages (in the form of `PackageURLs <https://github.com/package-url/packageurl-python>`_).
There is no notion of version ranges here: all package versions must be explicitly specified.

Because this concrete relationship is rarely available anywhere upstream, we have to *infer*
these values, thus the name.
As inferring something is not always perfect, an Inference also comes with a confidence score.

Improver
^^^^^^^^^

All the Improvers must inherit from ``Improver`` superclass and implement the
``interesting_advisories`` property and the ``get_inferences`` method.

Writing an improver
---------------------

Locate the Source File
^^^^^^^^^^^^^^^^^^^^^^^^

If the improver will be working on data imported by a specific importer, it  will be located in
the same file at :file:`vulnerabilites/importers/{importer-name.py}`.  Otherwise, if it is a
generic improver, create a new file :file:`vulnerabilites/improvers/{improver-name.py}`.

Explore Package Managers (Optional)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If your Improver depends on the discrete versions of a package, the package managers' VersionAPI
located at :file:`vulnerabilites/package_managers.py` could come in handy.  You'll need to
instantiate the relevant ``VersionAPI`` in the improver's constructor and use it later in the
implemented methods. See an already implemented improver (NginxBasicImprover) for an example usage.

Implement the ``interesting_advisories`` Property
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This property is intended to return a QuerySet of ``Advisory`` on which the ``Improver`` is
designed to work.

For example, if the improver is designed to work on Advisories imported by ``ExampleImporter``,
the property can be implemented as

.. code-block:: python

    class ExampleBasicImprover(Improver):

        @property
        def interesting_advisories(self) -> QuerySet:
            return Advisory.objects.filter(created_by=ExampleImporter.qualified_name)

Implement the ``get_inferences`` Method
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The framework calls ``get_inferences`` method for every ``AdvisoryData`` that is obtained from
the ``Advisory`` QuerySet returned by the ``interesting_advisories`` property.

It is expected to return an iterable of ``Inference`` objects for the given ``AdvisoryData``. To
avoid storing a lot of Inferences in memory, it is preferable to yield from this method.

A very simple Improver that processes all Advisories to create the minimal relationships that can
be obtained by existing data can be found at :file:`vulnerabilites/improvers/default.py`, which is
an example of a generic improver.  For a more sophisticated and targeted example, you can look
at an already implemented improver (e.g., :file:`vulnerabilites/importers/nginx.py`).

Improvers are not limited to improving discrete versions and may also improve ``aliases``.
One such example, improving the importer written in the :ref:`importer tutorial
<tutorial_add_a_new_importer>`, is shown below.

.. code-block:: python

    from datetime import datetime
    from datetime import timezone
    from typing import Iterable

    import requests
    from django.db.models.query import QuerySet
    from packageurl import PackageURL
    from univers.version_range import NginxVersionRange
    from univers.versions import SemverVersion

    from vulnerabilities.importer import AdvisoryData
    from vulnerabilities.improver import MAX_CONFIDENCE
    from vulnerabilities.improver import Improver
    from vulnerabilities.improver import Inference
    from vulnerabilities.models import Advisory
    from vulnerabilities.severity_systems import SCORING_SYSTEMS


    class ExampleImporter(Importer):
        ...


    class ExampleAliasImprover(Improver):
        @property
        def interesting_advisories(self) -> QuerySet:
            return Advisory.objects.filter(created_by=ExampleImporter.qualified_name)

        def get_inferences(self, advisory_data) -> Iterable[Inference]:
            for alias in advisory_data.aliases:
                new_aliases = fetch_additional_aliases(alias)
                aliases = new_aliases + [alias]
                yield Inference(aliases=aliases, confidence=MAX_CONFIDENCE)


    def fetch_additional_aliases(alias):
        alias_map = {
            "CVE-2021-23017": ["PYSEC-1337", "CERTIN-1337"],
            "CVE-2021-1234": ["ANONSEC-1337", "CERTDES-1337"],
        }
        return alias_map.get(alias)


.. note::

   | Use ``make valid`` to format your new code using black and isort automatically.
   | Use ``make check`` to check for formatting errrors.

Register the Improver
^^^^^^^^^^^^^^^^^^^^^^

Finally, register your improver in the improver registry at
:file:`vulnerabilites/improvers/__init__.py`.

.. code-block:: python
   :emphasize-lines: 7

    from vulnerabilities import importers
    from vulnerabilities.improvers import default

    IMPROVERS_REGISTRY = [
        default.DefaultImprover,
        importers.nginx.NginxBasicImprover,
        importers.example.ExampleAliasImprover,
    ]

    IMPROVERS_REGISTRY = {x.qualified_name: x for x in IMPROVERS_REGISTRY}

Congratulations! You've written your first improver.

Run Your First Improver
^^^^^^^^^^^^^^^^^^^^^^^^^^

If everything went well, you'll see your improver in the list of available improvers.

.. code-block:: console
   :emphasize-lines: 6

    $ ./manage.py improve --list

    Vulnerability data can be processed by these available improvers:
    vulnerabilities.improvers.default.DefaultImprover
    vulnerabilities.importers.nginx.NginxBasicImprover
    vulnerabilities.importers.example.ExampleAliasImprover

Before running the improver, make sure you have imported the data. An improver cannot improve if
there is nothing imported.

.. code-block:: console

    $ ./manage.py import vulnerabilities.importers.example.ExampleImporter

    Importing data using vulnerabilities.importers.example.ExampleImporter
    Successfully imported data using vulnerabilities.importers.example.ExampleImporter

Now, run the improver.

.. code-block:: console

   $ ./manage.py improve vulnerabilities.importers.example.ExampleAliasImprover

    Improving data using vulnerabilities.importers.example.ExampleAliasImprover
    Successfully improved data using vulnerabilities.importers.example.ExampleAliasImprover

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

Invoke the improve command now and you'll see (in a fresh database, after importing):

.. code-block:: console

    $ ./manage.py improve vulnerabilities.importers.example.ExampleAliasImprover

    Improving data using vulnerabilities.importers.example.ExampleAliasImprover
    Running improver: vulnerabilities.importers.example.ExampleAliasImprover
    Improving advisory id: 1
    New alias for <Vulnerability: VULCOID-23dd9060-3bc0-4454-bfbd-d16c08a966a6>: PYSEC-1337
    New alias for <Vulnerability: VULCOID-23dd9060-3bc0-4454-bfbd-d16c08a966a6>: CVE-2021-23017
    New alias for <Vulnerability: VULCOID-23dd9060-3bc0-4454-bfbd-d16c08a966a6>: CERTIN-1337
    Improving advisory id: 2
    New alias for <Vulnerability: VULCOID-fae4e06e-4815-45fe-ae95-8d2356ffb5b9>: CERTDES-1337
    New alias for <Vulnerability: VULCOID-fae4e06e-4815-45fe-ae95-8d2356ffb5b9>: ANONSEC-1337
    New alias for <Vulnerability: VULCOID-fae4e06e-4815-45fe-ae95-8d2356ffb5b9>: CVE-2021-1234
    Finished improving using vulnerabilities.importers.example.ExampleAliasImprover.
    Successfully improved data using vulnerabilities.importers.example.ExampleAliasImprover

.. note::

   Even though CVE-2021-23017 and CVE-2021-1234 are not supplied by this improver, the output above shows them
   because we left out running the ``DefaultImprover`` in the example. The ``DefaultImprover``
   inserts minimal data found via the importers in the database (here, the above two CVEs). Run
   importer, DefaultImprover and then your improver in this sequence to avoid this anomaly.
