.. _api_admin:

API usage administration for on-premise deployments
====================================================

Enable the API key authentication
------------------------------------

There is a setting VULNERABLECODEIO_REQUIRE_AUTHENTICATION for this. Use it this
way::

    $ VULNERABLECODEIO_REQUIRE_AUTHENTICATION=1 make run


Create an API key-only user
------------------------------------

This can be done in the admin and from the command line::

    $ ./manage.py create_api_user --email "p4@nexb.com" --first-name="Phil" --last-name "Goel"
    User p4@nexb.com created with API key: ce8616b929d2adsddd6146346c2f26536423423491
