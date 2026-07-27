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

API client configuration
----------------------------

API clients must send a `User-Agent` header that matches the value of the
`VCIO_USER_AGENT` setting.

Add the following to your .env file::

    VCIO_USER_AGENT="vulnerablecode-client"

Requests without the configured User-Agent header will be rejected with 403 Forbidden.

API rate limiting
-------------------

The API uses request throttling to protect the service from excessive traffic.

The rate limits can be configured in the .env file::

    THROTTLE_RATE_ANON=10/minute
    THROTTLE_RATE_UI=15/minute
    THROTTLE_RATE_USER_HIGH=1/second
    THROTTLE_RATE_USER_MEDIUM=30/minute
    THROTTLE_RATE_USER_LOW=20/minute

Configure Altcha protection
----------------------------

VulnerableCode uses Altcha to protect forms from automated abuse without
relying on third-party CAPTCHA services

To enable Altcha, add the following setting to your .env file::

    ALTCHA_HMAC_KEY=32-byte secret
