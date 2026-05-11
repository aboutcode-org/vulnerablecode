.. _api_v3_usage:

Package Endpoint
================

We are migrating from **API v1** to **API v3**.

Previously, the ``/api/packages`` endpoint exposed multiple routes:

- ``bulk_search``
- ``bulk_lookup``
- ``lookup``
- ``all``

In **API v3**, all these capabilities are consolidated into a **single endpoint**:

::

    POST /api/v3/packages


Pagination
----------

Responses from the package endpoint are **always paginated**, with **10 results per page**.

Each response includes:

- ``count`` — total number of results
- ``next`` — URL for the next page
- ``previous`` — URL for the previous page

If a package is associated with **more than 100 advisories**, the response will include:

- ``affected_by_vulnerabilities_url`` instead of ``affected_by_vulnerabilities``
- ``fixing_vulnerabilities_url`` instead of ``fixing_vulnerabilities``


Getting All Vulnerable Packages
-------------------------------

Instead of calling ``/api/packages/all``, call the v3 endpoint with an empty ``purls`` list.

::

    POST /api/v3/packages

    {
        "purls": []
    }

Example response:

::

    {
        "count": 596,
        "next": "http://example.com/api/v3/packages?page=2",
        "previous": null,
        "results": [
            "pkg:npm/626@1.1.1",
            "pkg:npm/aedes@0.35.0",
            "pkg:npm/airbrake@0.3.8",
            "pkg:npm/angular-http-server@1.4.3",
            "pkg:npm/apex-publish-static-files@2.0.0",
            "pkg:npm/atob@2.0.3",
            "pkg:npm/augustine@0.2.3",
            "pkg:npm/backbone@0.3.3",
            "pkg:npm/base64-url@1.3.3",
            "pkg:npm/base64url@2.0.0"
        ]
    }


Bulk Search (Replacement)
-------------------------

Instead of calling ``/api/packages/bulk_search``, use:

::

    POST /api/v3/packages

Parameters:

- ``purls`` — list of package URLs to query
- ``details`` — boolean (default: ``false``)
- ``ignore_qualifiers_subpath`` — boolean (default: ``false``)

The ``ignore_qualifiers_subpath`` flag replaces the previous ``plain_purl`` parameter.
When set to ``true``, qualifiers and subpaths in PURLs are ignored.


Get Only Vulnerable PURLs
~~~~~~~~~~~~~~~~~~~~~~~~~

::

    POST /api/v3/packages

    {
        "purls": ["pkg:npm/atob@2.0.3", "pkg:pypi/sample@2.0.0"],
        "details": false
    }

Example response:

::

    {
        "count": 1,
        "next": null,
        "previous": null,
        "results": [
            "pkg:npm/atob@2.0.3"
        ]
    }


Get Detailed Vulnerability Information
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    POST /api/v3/packages

    {
        "purls": ["pkg:npm/atob@2.0.3", "pkg:pypi/sample@2.0.0"],
        "details": true
    }

Example response:

::

    {
        "count": 1,
        "next": null,
        "previous": null,
        "results": [
            {
                "purl": "pkg:npm/atob@2.0.3",
                "affected_by_vulnerabilities": [
                    {
                    "advisory_id": "GHSA-g5vw-3h65-2q3v",
                    "aliases": [],
                    "weighted_severity": null,
                    "exploitability_score": null,
                    "risk_score": null,
                    "summary": "Access control vulnerable to user data",
                    "fixed_by_packages": [
                        "pkg:pypi/accesscontrol@7.2"
                    ],
                },
                ],
                "fixing_vulnerabilities": [],
                "next_non_vulnerable_version": "2.1.0",
                "latest_non_vulnerable_version": "2.1.0",
                "risk_score": null
            }
        ]
    }


Using Approximate Matching
~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    POST /api/v3/packages

    {
        "purls": ["pkg:npm/atob@2.0.3?foo=bar"],
        "ignore_qualifiers_subpath": true,
        "details": true
    }

Example response:

::

    {
        "count": 1,
        "next": null,
        "previous": null,
        "results": [
            {
                "purl": "pkg:npm/atob@2.0.3",
                "affected_by_vulnerabilities": [
                {
                    "advisory_id": "GHSA-g5vw-3h65-2q3v",
                    "aliases": [],
                    "weighted_severity": null,
                    "exploitability_score": null,
                    "risk_score": null,
                    "summary": "Access control vulnerable to user data",
                    "fixed_by_packages": [
                        "pkg:pypi/accesscontrol@7.2"
                    ],
                }
                ],
                "fixing_vulnerabilities": [],
                "next_non_vulnerable_version": "2.1.0",
                "latest_non_vulnerable_version": "2.1.0",
                "risk_score": null
            }
        ]
    }


Advisory Endpoint
=================

Retrieve advisories for one or more PURLs:

::

    POST /api/v3/advisories

    {
        "purls": ["pkg:npm/atob@2.0.3", "pkg:pypi/sample@2.0.0"]
    }

Responses are paginated (10 results per page) and include ``next`` and ``previous`` links.


Affected-By Advisories Endpoint
===============================

Retrieve advisories that **affect (impact)** a given PURL:

::

    GET /api/v3/affected-by-advisories?purl=<purl>

Example:

::

    GET /api/v3/affected-by-advisories?purl=pkg:npm/atob@2.0.3


Fixing Advisories Endpoint
==========================

Retrieve advisories that are **fixed by** a given PURL:

::

    GET /api/v3/fixing-advisories?purl=<purl>

Example:

::

    GET /api/v3/fixing-advisories?purl=pkg:npm/atob@2.1.0
