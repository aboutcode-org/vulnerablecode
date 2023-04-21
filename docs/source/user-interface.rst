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

    `https://public.vulnerablecode.io/packages/search <https://public.vulnerablecode.io/packages/search>`_

How to search by packages:

    1. Go to the URL: `https://public.vulnerablecode.io/packages/search <https://public.vulnerablecode.io/packages/search>`_
    2. Enter the package URL or purl prefix fragment such as ``pkg:pypi``
       or by package name in the search box.
    3. Click on the search button.

The search results will be displayed in the table below the search box.

        .. image:: images/pkg_search.png

Click on the package URL to view the package details.

        .. image:: images/pkg_details.png


.. _vuln-search:

Search by vulnerabilities
---------------------------

The search by vulnerabilities is a very powerful feature of
VulnerableCode. It allows you to search for vulnerabilities by the
VCID itself. It also allows you to search for
vulnerabilities by the CVE, GHSA, CPEs etc or by the
fragment of these identifiers like ``CVE-2021``.

The search by vulnerabilities is available at the following URL:

    `https://public.vulnerablecode.io/vulnerabilities/search <https://public.vulnerablecode.io/vulnerabilities/search>`_

How to search by vulnerabilities:

    1. Go to the URL: `https://public.vulnerablecode.io/vulnerabilities/search <https://public.vulnerablecode.io/vulnerabilities/search>`_
    2. Enter the VCID, CVE, GHSA, CPEs etc. in the search box.
    3. Click on the search button.

The search results will be displayed in the table below the search box.

    .. image:: images/vuln_search.png

Click on the VCID to view the vulnerability details.

    .. image:: images/vuln_details.png

Affected packages tab shows the list of packages affected by the
vulnerability.

    .. image:: images/vuln_affected_packages.png

Fixed by packages tab shows the list of packages that fix the
vulnerability.

    .. image:: images/vuln_fixed_packages.png
