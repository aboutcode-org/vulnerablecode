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

.. _Package Vulnerabilities Query:

Query for Package Vulnerabilities
------------------------------------

The package endpoint allows you to query vulnerabilities by package using a
purl or purl fields.

Sample python script::

    import requests

    # Query by purl
    resp = requests.get(
        "https://public.vulnerablecode.io/api/packages?purl=pkg:maven/log4j/log4j@1.2.27",
        headers={"Authorization": "Token 123456789"},
    ).json()

    # Query by purl type, get all the vulnerable maven packages
    resp = requests.get(
        "https://public.vulnerablecode.io/api/packages?type=maven",
        headers={"Authorization": "Token 123456789"},
    ).json()

Sample using curl::

    curl -X GET -H 'Authorization: Token <YOUR TOKEN>' https://public.vulnerablecode.io/api/packages?purl=pkg:maven/log4j/log4j@1.2.27


The response will be a list of packages, these are packages
that are affected by and/or that fix a vulnerability.


.. _Package Bulk Search:

Package Bulk Search
---------------------


The package bulk search endpoint allows you to search for purls in bulk. You can
pass a list of purls in the request body and the endpoint will return a list of
purls with vulnerabilities.


You can pass a list of ``purls`` in the request body. Each package should be a
valid purl string.

You can also pass options like ``purl_only`` and ``plain_purl`` in the request.
``purl_only`` will return only a list of vulnerable purls from the purls received in request.
``plain_purl`` allows you to query the API using plain purls by removing qualifiers
and subpath from the purl.

The request body should be a JSON object with the following structure::

    {
        "purls": [
            "pkg:pypi/flask@1.2.0",
            "pkg:npm/express@1.0"
        ],
        "purl_only": false,
        "plain_purl": false,
    }

Sample python script::

    import requests

    request_body = {
        "purls": [
            "pkg:npm/grunt-radical@0.0.14"
        ],
    }

    resp = requests.post('https://public.vulnerablecode.io/api/packages/bulk_search', json= request_body, headers={'Authorization': "Token 123456789"}).json()


The response will be a list of packages, these are packages
that are affected by and/or that fix a vulnerability.

.. _CPE Bulk Search:

CPE Bulk Search
---------------------


The CPE bulk search endpoint allows you to search for packages in bulk.
You can pass a list of packages in the request body and the endpoint will
return a list of vulnerabilities.


You can pass a list of ``cpes`` in the request body. Each cpe should be a
non empty string and a valid CPE.


The request body should be a JSON object with the following structure::

    {
        "cpes": [
            "cpe:2.3:a:apache:struts:2.3.1:*:*:*:*:*:*:*",
            "cpe:2.3:a:apache:struts:2.3.2:*:*:*:*:*:*:*"
        ]
    }

Sample python script::

    import requests

    request_body = {
        "cpes": [
            "cpe:2.3:a:apache:struts:2.3.1:*:*:*:*:*:*:*"
        ],
    }

    resp = requests.post('https://public.vulnerablecode.io/api/cpes/bulk_search', json= request_body, headers={'Authorization': "Token 123456789"}).json()

The response will be a list of vulnerabilities that have the following CPEs.


API endpoints reference
--------------------------

There are two primary endpoints:

- packages/: this is the main endpoint where you can lookup vulnerabilities by package.

- vulnerabilities/: to lookup by vulnerabilities

And two secondary endpoints, used to query vulnerability aliases (such as CVEs)
and vulnerability by CPEs: cpes/ and aliases/


.. list-table:: Table for the main API endpoints
   :widths: 30 40 30
   :header-rows: 1

   * - Endpoint
     - Query Parameters
     - Expected Output
   * - ``/api/packages``
     -
       - ``purl`` (string) = package-url of the package
       - ``type`` (string) = type of the package
       - ``namespace`` (string) = namespace of the package
       - ``name`` (string) = name of the package
       - ``version`` (string) = version of the package
       - ``qualifiers`` (string) = qualifiers of the package
       - ``subpath`` (string) = subpath of the package
       - ``page`` (integer) = page number of the response
       - ``page_size`` (integer) = number of packages in each page
     - Return a list of packages using a package-url (purl) or a combination of
       type, namespace, name, version, qualifiers, subpath purl fields. See the
       `purl specification <https://github.com/package-url/purl-spec>`_ for more details. See example at :ref:`Package Vulnerabilities Query` section for more details.
   * - ``/api/packages/bulk_search``
     - Refer to package bulk search section :ref:`Package Bulk Search`
     - Return a list of packages
   * - ``/api/vulnerabilities/``
     -
       - ``vulnerability_id`` (string) = VCID (VulnerableCode Identifier) of the vulnerability
       - ``page`` (integer) = page number of the response
       - ``page_size`` (integer) = number of vulnerabilities in each page
     - Return a list of vulnerabilities
   * - ``/api/cpes``
     -
       - ``cpe`` (string) = value of the cpe
       - ``page`` (integer) = page number of the response
       - ``page_size`` (integer) = number of cpes in each page
     - Return a list of vulnerabilities
   * - ``/api/cpes/bulk_search``
     - Refer to CPE bulk search section :ref:`CPE Bulk Search`
     - Return a list of cpes
   * - ``/api/aliases``
     -
       - ``alias`` (string) = value of the alias
       - ``page`` (integer) = page number of the response
       - ``page_size`` (integer) = number of aliases in each page
     - Return a list of vulnerabilities

.. list-table:: Table for other API endpoints
   :widths: 30 40 30
   :header-rows: 1

   * - Endpoint
     - Query Parameters
     - Expected Output
   * - ``/api/packages/{id}``
     -
       - ``id`` (integer) = internal primary id of the package
     - Return a package with the given id
   * - ``/api/packages/all``
     - No parameter required
     - Return a list of all vulnerable packages
   * - ``/api/vulnerabilities/{id}``
     -
       - ``id`` (integer) = internal primary id of the vulnerability
     - Return a vulnerability with the given id
   * - ``/api/aliases/{id}``
     -
       - ``id`` (integer) = internal primary id of the alias
     - Return an alias with the given id
   * - ``/api/cpes/{id}``
     -
       - ``id`` = internal primary id of the cpe
     - Return a cpe with the given id

Miscellaneous
----------------

The API is paginated and the default page size is 100. You can change the page size
by passing the ``page_size`` parameter. You can also change the page number by passing
the ``page`` parameter.
