.. _contributing:

Contributing to VulnerableCode
=================================

Thank you so much for being so interested in contributing to VulnerableCode. We
are always on the lookout for enthusiastic contributors like you who can make
our project better, and we are willing to lend a helping hand if you have any
questions or need guidance along the way. That being said, here are a few
resources to help you get started.

.. note::
    By contributing to the VulnerableCode project, you agree to the Developer
    `Certificate of Origin <https://developercertificate.org/>`_.


Do Your Homework
----------------

Before adding a contribution or create a new issue, take a look at the project’s
`README <https://github.com/nexB/vulnerablecode>`_, read through our
`documentation <https://vulnerablecode.readthedocs.io/en/latest/>`_,
and browse existing `issues <https://github.com/nexB/vulnerablecode/issues>`_,
to develop some understanding of the project and confirm whether a given
issue/feature has previously been discussed.

Ways to Contribute
------------------

Contributing to the codebase is not the only way to add value to VulnerableCode or
join our community. Below are some examples to get involved:

First Timers
^^^^^^^^^^^^

You are here to help, but you are a new contributor! No worries, we always
welcome newcomer contributors. We maintain some
`good first issues <https://github.com/nexB/vulnerablecode/labels/good%20first%20issue>`_
and encourage new contributors to work on those issues for a smooth start.

.. tip::
    If you are an open-source newbie, make sure to check the extra resources at
    the bottom of this page to get the hang of the contribution process!

Code Contributions
^^^^^^^^^^^^^^^^^^

For more established contributors, you can contribute to the codebase in several ways:

- Report a `bug <https://github.com/nexB/vulnerablecode/issues>`_; just remember to be as
  specific as possible.
- Submit a `bug fix <https://github.com/nexB/vulnerablecode/labels/bug>`_ for any existing
  issue.
- Create a `new issue <https://github.com/nexB/vulnerablecode/issues>`_ to request a
  feature, submit a feedback, or ask a question.

.. note::
    Make sure to check existing `issues <https://github.com/nexB/vulnerablecode/issues>`_,
    to confirm whether a given issue or a question has previously been
    discussed.

Documentation Improvements
^^^^^^^^^^^^^^^^^^^^^^^^^^

Documentation is a critical aspect of any project that is usually neglected or
overlooked. We value any suggestions to improve
`vulnerablecode documentation <https://vulnerablecode.readthedocs.io/en/latest/>`_.

.. tip::
    Our documentation is treated like code. Make sure to check our
    `writing guidelines <https://scancode-toolkit.readthedocs.io/en/latest/contribute/contrib_doc.html>`_
    to help guide new users.

Other Ways
^^^^^^^^^^

You want to contribute to other aspects of the VulnerableCode project, and you
cannot find what you are looking for! You can always discuss new topics, ask
questions, and interact with us and other community members on
`AboutCode Gitter <https://gitter.im/aboutcode-org/discuss>`_ and `VulnerableCode Gitter <https://gitter.im/aboutcode-org/vulnerablecode>`_

Helpful Resources
-----------------

- Review our `comprehensive guide <https://scancode-toolkit.readthedocs.io/en/latest/contribute/index.html>`_
  for more details on how to add quality contributions to our codebase and documentation
- Check this free resource on `how to contribute to an open source project on github <https://egghead.io/courses/how-to-contribute-to-an-open-source-project-on-github>`_
- Follow `this wiki page <https://aboutcode.readthedocs.io/en/latest/contributing/writing_good_commit_messages.html>`_
  on how to write good commit messages
- `Pro Git book <https://git-scm.com/book/en/v2>`_
- `How to write a good bug report <https://www.softwaretestinghelp.com/how-to-write-good-bug-report/>`_

.. _tutorial_add_a_new_importer:

Add a new importer
-------------------

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

All importers are located in the :file:`vulnerabilites/importers` directory.
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
   expressions, see https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/

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

   It is possible that the versioning scheme you are targeting has not yet been
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
   | Use ``make check`` to check for formatting errors.

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

.. _tutorial_add_a_new_improver:

Add a new improver
---------------------

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
``interesting_advisories`` property and the ``get_inferences`` method,
unless they are not improving advisory data. In this case they should override
``is_custom_improver`` property to True and implement the ``run`` method.


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
located at :file:`vulnerabilites/package_managers.py` could come in handy.  You will need to
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

Congratulations! You have written your first improver.

Run Your First Improver
^^^^^^^^^^^^^^^^^^^^^^^^^^

If everything went well, you will see your improver in the list of available improvers.

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

Invoke the improve command now and you will see (in a fresh database, after importing):

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
