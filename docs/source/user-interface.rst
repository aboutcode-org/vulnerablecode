.. _user-interface:

User Interface
================

.. _pkg-search:

Search by packages
------------------

The search by packages is a very powerful feature of
VulnerableCode. It allows you to search for packages by the
package URL or purl prefix fragment such as
``pkg:pypi`` or by package name.

The search by packages is available at the following URL:

    `https://public.vulnerablecode.io <https://public.vulnerablecode.io>`_

How to search by packages:

    1. Go to the URL: `https://public.vulnerablecode.io/ <https://public.vulnerablecode.io/>`_
    2. Enter the package URL or purl prefix fragment such as ``pkg:pypi/aubio``
       or by package name in the search box.
    3. Click on the search button.

The search results will be displayed in the table below the search box.

        .. image:: images/pkg_search.png

Click on the package URL to view the package details.

        .. image:: images/pkg_details.png


.. _vuln-search:

Navigate to Advisories
-----------------------

You can directly navigate to an advisory page by specifying the datasource_id (for example, nvd)
and advisory_id (for example, CVE-2026-23918). `https://public.vulnerablecode.io/advisories/datasource_id/advisory_id`

For example:
    - `https://public.vulnerablecode.io/advisories/github_osv/GHSA-6xcx-gx7r-rccj <https://public.vulnerablecode.io/advisories/github_osv/GHSA-6xcx-gx7r-rccj>`_
    - `https://public.vulnerablecode.io/advisories/nvd/CVE-2026-23918 <https://public.vulnerablecode.io/advisories/nvd/CVE-2023-40024>`_
