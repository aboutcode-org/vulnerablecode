.. _api:

API overview
========================


Browse the Open API documentation
------------------------------------

- https://public.vulnerablecode.io/api/docs/ for documentation with Swagger
- https://public.vulnerablecode.io/api/schema/ for the OpenAPI schema


How to use OpenAPI documentation
--------------------------------------

The API documentation is available at https://public.vulnerablecode.io/api/docs/.
To use the endpoints you need to authenticate with an API key. Request your API key
from https://public.vulnerablecode.io/account/request_api_key/. Once you have
your API key, click on the ``Authorize`` button on the top right of the page and enter
your API key in the ``value`` field with ``Token`` prefix, so if your token is "1234567890abcdef"
then you have to enter this: ``Token 1234567890abcdef``.

.. _Vulnerable Packages Query:

Query for Vulnerable Packages
------------------------------------

The package endpoint allows you to query vulnerable packages using a
purl or purl fields.

Sample python script::

    import requests

    # Query by purl
    resp = requests.post(
        "https://public.vulnerablecode.io/api/v3/packages/",
        headers={"Authorization": "Token 123456789", "User-Agent": "VCIO_API_AGENT"},
        json={
            "purls": ["pkg:npm/atob@2.0.3?foo=bar"],
            "ignore_qualifiers_subpath": True,
            "details": True
        }
    ).json()

Sample using curl::

    curl -X POST "https://public.vulnerablecode.io/api/v3/packages/" \
      -H "Authorization: Token <YOUR_TOKEN>" \
      -H "Content-Type: application/json" \
      -H "User-Agent: VCIO_API_AGENT" \
      -d '{
        "purls": [
          "pkg:pypi/flask@2.3.2"
        ],
        "ignore_qualifiers_subpath": true,
        "details": true,
        "reachability": true
      }'

The response will be a list of packages, these are packages
that are affected by and/or that fix a vulnerability advisory.

API endpoints reference
--------------------------

.. list-table:: Table for the main API endpoints
   :widths: 30 40 30
   :header-rows: 1

   * - Endpoint
     - Query Parameters
     - Expected Output
   * - POST ``/api/v3/packages/``
     -
       - ``purls`` (array of strings) = List of package URLs ( a package-url (purl) or a combination of
         type, namespace, name, version, qualifiers, subpath purl fields. See the
         `purl specification <https://github.com/package-url/purl-spec>`_ for more details. )
       - ``details`` (boolean) = Display all details about the packages provided
       - ``ignore_qualifiers_subpath`` (boolean) = Ignore qualifiers/subpaths
       - ``max_advisories`` (integer) = Maximum advisories to return
       - ``reachability`` (boolean) = Display details about reachability
         (introduced_in_patches and fixed_in_patches)
     - Return a list of vulnerable packages
   * - POST ``/api/v3/advisories/``
     -
        - ``purls`` (array of strings) = list of package urls
     - Returns a list of advisories related to the provided packages
   * - GET ``/api/v3/affected-by-advisories/``
     -
       - ``page`` (string) = A page number within the paginated result set.
       - ``page_size`` (integer) = Number of results to return per page.
       - ``search`` (string) = A search term.
     - Returns a paginated list of advisories vulnerabilities that affect given packages.
   * - GET ``/api/v3/affected-by-advisories/{id}/``
     -
       - ``id`` (string) = A unique integer value identifying this advisory v2.
     - Returns a specific advisory that affect a given package.
   * - GET ``/api/v3/fixing-advisories/``
     -
       - ``page`` (integer) = A page number within the paginated result set.
       - ``page_size`` (integer) = Number of results to return per page.
       - ``search`` (string) = A search term.
     - Return a paginated list of advisories that fix a given package.
   * - GET ``/api/v3/fixing-advisories/{id}/``
     -
       - ``id`` (string) = A unique integer value identifying this advisory v2.
     - Returns a specific advisory that fix a given package.
   * - GET ``/api/v3/package-types/``
     -
     - Return a list of to all the packages types in the database.

Miscellaneous
----------------

The API is paginated and the default page size is 100. You can change the page size
by passing the ``page_size`` parameter. You can also change the page number by passing
the ``page`` parameter.
