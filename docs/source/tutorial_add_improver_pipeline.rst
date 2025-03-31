.. _tutorial_add_improver_pipeline:

Add pipeline to improve/enhance data
=====================================

TL;DR
-------

#. Create a new file ``{improver_name}.py`` inside **vulnerabilities/pipelines/**.
#. Create a new improver pipeline by inheriting **VulnerableCodePipeline** defined
   in **vulnerabilities.pipelines**.
#. Implement ``steps`` **classmethod** to define what function to run and in which order.
#. Implement the individual function defined in ``steps``
#. Add the newly created pipeline to the improvers registry at
   **vulnerabilities/improvers/__init__.py**.

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

This tutorial contains all the things one should know to quickly implement an improver pipeline.


Prerequisites
-------------

The new improver design lets you do all sorts of cool improvements and enhancements.
Some of those are:

* Let's suppose you have a certain number of packages and vulnerabilities in your database,
  and you want to make sure that the packages being shown in VulnerableCode do indeed exist
  upstream. Oftentimes, we come across advisory data that contains made-up package versions.
  We can write (well, we already have) a pipeline that iterates through all the packages in
  VulnerableCode and labels them as ghost packages if they don't exist upstream.


- A basic security advisory only contains CVE/aliases, summary, fixed/affected version, and
  severity. But now we can use the new pipeline to enhance the vulnerability info with exploits from
  various sources like ExploitDB, Metasploit, etc.


* Likewise, we can have more pipelines to flag malicious/yanked packages.


So you see, the new improver pipeline is very powerful in what you can achieve, but as always, with
great power comes great responsibility. By design, the new improver are unconstrained, and you must
be absolutely sure of what you're doing and should have robust tests for these pipelines in place.


Writing an Improver Pipeline
-----------------------------

**Scenario:** Suppose we come around a source that curates and stores the list of packages that
don't exist upstream and makes it available through the REST API endpoint
https://example.org/api/non-existent-packages, which gives a JSON response with a list of
non-existent packages.

Let's write a pipeline that will use this source to flag these non-existent package as
ghost package.


Create file for the new improver pipeline
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

All pipelines, including the improver pipeline, are located in the
`vulnerabilities/pipelines/
<https://github.com/aboutcode-org/vulnerablecode/tree/main/vulnerabilities/pipelines>`_ directory.

The improver pipeline is implemented by subclassing `VulnerableCodePipeline`.

Specify the importer license
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If the improver pipeline scrapes data off the internet, we need to track the license for
the scraped data to make sure that we can legally use it.

Populate the ``spdx_license_expression`` with the appropriate value. The SPDX license identifiers
can be found at `ScanCode LicenseDB <https://scancode-licensedb.aboutcode.org/>`_.

.. note::
   An SPDX license identifier by itself is a valid license expression. In case you need more
   complex expressions, see https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/


Add skeleton for new pipeline
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In this scenario pipeline needs to do two thing fetch raw data and use that to flag those packages.

At this point improver will look like this:

.. code-block:: python
    :caption: vulnerabilities/pipelines/flag_ghost_package_with_example_org.py
    :linenos:
    :emphasize-lines: 14-15, 18-19, 21-22

    from vulnerabilities.pipelines import VulnerableCodePipeline

    class FlagGhostPackagesWithExampleOrg(VulnerableCodePipeline):
        """Example improver pipeline to flag ghost packages."""

        pipeline_id = "flag_ghost_package_with_example_org"

        license_url = "https://exmaple.org/license/"
        spdx_license_expression = "CC-BY-4.0"

        @classmethod
        def steps(cls):
            return (
                cls.fetch_response,
                cls.flag_ghost_packages,
            )

        def fetch_response(self):
            raise NotImplementedError

        def flag_ghost_packages(self):
            raise NotImplementedError


Implement the steps
~~~~~~~~~~~~~~~~~~~

We will evolve our high level design by implementing ``fetch_response`` and ``flag_ghost_packages``
methods.

.. code-block:: python
    :caption: vulnerabilities/pipelines/flag_ghost_package_with_example_org.py
    :linenos:
    :emphasize-lines: 20-32, 34-42

    from vulnerabilities.models import Package
    from vulnerabilities.pipelines import VulnerableCodePipeline


    class FlagGhostPackagesWithExampleOrg(VulnerableCodePipeline):
        """Example improver pipeline to flag ghost packages."""

        pipeline_id = "flag_ghost_package_with_example_org"

        license_url = "https://exmaple.org/license/"
        spdx_license_expression = "CC-BY-4.0"

        @classmethod
        def steps(cls):
            return (
                cls.fetch_response,
                cls.flag_ghost_packages,
            )

        def fetch_response(self):
            # Since this is imaginary source we will mock the response
            # In actual implementation you need to use request library to get data.
            mock_response = {
                "non-existent": [
                    "pkg:npm/626@1.1.1",
                    "pkg:npm/bootstrap-tagsinput@0.8.0",
                    "pkg:npm/dojo@1.0.0",
                    "pkg:npm/dojo@1.1.0",
                    "pkg:npm/electron@1.8.0",
                ]
            }
            self.fetched_data = mock_response

        def flag_ghost_packages(self):
            non_existent_packages = self.fetched_data.get("non-existent", [])

            ghost_packages = Package.objects.filter(package_url__in=non_existent_packages)
            ghost_package_count = ghost_packages.count()

            ghost_packages.update(is_ghost=True)

            self.log(f"Successfully flagged {ghost_package_count:,d} ghost Packages")


.. attention::

   Implement ``on_failure`` to handle cleanup in case of pipeline failure.
   Cleanup of downloaded archives or cloned repos is necessary to avoid potential resource leakage.

.. note::

   | Use ``make valid`` to format your new code using black and isort automatically.
   | Use ``make check`` to check for formatting errors.


Register the Improver Pipeline
------------------------------

Finally, register your improver in the improver registry at
`vulnerabilities/improvers/__init__.py
<https://github.com/aboutcode-org/vulnerablecode/blob/main/vulnerabilities/improvers/__init__.py>`_


.. code-block:: python
    :caption: vulnerabilities/improvers/__init__.py
    :linenos:
    :emphasize-lines: 2, 6

    from vulnerabilities.pipeline import enhance_with_kev
    from vulnerabilities.pipeline import flag_ghost_package_with_example_org

    IMPROVERS_REGISTRY = [
        enhance_with_kev.VulnerabilityKevPipeline,
        flag_ghost_package_with_example_org.FlagGhostPackagesWithExampleOrg,
    ]

    IMPROVERS_REGISTRY = {
        x.pipeline_id if issubclass(x, VulnerableCodePipeline) else x.qualified_name: x
        for x in IMPROVERS_REGISTRY
    }


Congratulations! You have written your first improver pipeline.

Run Your First Improver Pipeline
--------------------------------

If everything went well, you will see your improver in the list of available improvers.

.. code-block:: console
   :emphasize-lines: 5

    $ ./manage.py improve --list

    Vulnerability data can be processed by these available improvers:
    enhance_with_kev
    flag_ghost_package_with_example_org

Now, run the improver.

.. code-block:: console

    $ ./manage.py improve flag_ghost_package_with_example_org

    Improving data using flag_ghost_package_with_example_org
    INFO 2024-10-17 14:37:54.482 Pipeline [FlagGhostPackagesWithExampleOrg] starting
    INFO 2024-10-17 14:37:54.482 Step [fetch_response] starting
    INFO 2024-10-17 14:37:54.482 Step [fetch_response] completed in 0 seconds
    INFO 2024-10-17 14:37:54.482 Step [flag_ghost_packages] starting
    INFO 2024-10-17 14:37:54.488 Successfully flagged 5 ghost Packages
    INFO 2024-10-17 14:37:54.488 Step [flag_ghost_packages] completed in 0 seconds
    INFO 2024-10-17 14:37:54.488 Pipeline completed in 0 seconds


See :ref:`command_line_interface` for command line usage instructions.

.. tip::

   If you need to improve package vulnerability relations created using a certain pipeline,
   simply use the **pipeline_id** to filter out only those items. For example, if you want
   to improve only those **AffectedByPackageRelatedVulnerability** entries that were created
   by npm_importer pipeline, you can do so with the following query:

   .. code-block:: python

      AffectedByPackageRelatedVulnerability.objects.filter(created_by=NpmImporterPipeline.pipeline_id)

.. note::

   Make sure to use properly optimized query sets, and wherever needed, use paginated query sets.
