.. _api:

API overview
========================



Enable the API key authentication
------------------------------------

There is a setting VULNERABLECODEIO_REQUIRE_AUTHENTICATION for this. Use it this
way::

    $ VULNERABLECODEIO_REQUIRE_AUTHENTICATION=1 make run


Create an API key-only user
------------------------------------

This can be done in the admin and from the command line::

    $ ./manage.py create-api-user --email "p4@nexb.com" --first-name="Phil" --last-name "Goel"
    User p4@nexb.com created with API key: ce8616b929d2adsddd6146346c2f26536423423491


Access the API using curl
-----------------------------

    curl -X GET -H 'Authorization: Token <YOUR TOKEN> ' http://public.vulnerablecode.io/api/


API endpoints
---------------


There are two primary endpoints:

- packages/: this is the main endpoint where you can lookup vulnerabilities by package.

- vulnerabilities.: for lookup by vulnerabilities

And two secondary endpoints, used to query aliases and CPEs: cpes/ and alias/

