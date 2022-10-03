Release notes
=============

Version v30.0.0
----------------

This is a major version that is not backward compatible.

- We refactored the core processing with Importers that import data and Improvers that
  transform imported data and convert that in Vulnerabilities and Packages. Improvers can
  also improve and refine imported and existing data as well as enrich data using external
  data sources. The migration to this new architecture is under way and not all importers
  are available.

  Because of these extensive changes, it is not possible to migrate existing imported
  data to the new schema. You will need instead to restart imports from an empty database
  or access the new public.vulnerablecode.io live instance. We also provide a database dump.

- You can track the progress of this refactoring in this issue:
  https://github.com/nexB/vulnerablecode/issues/597 

- We added new data sources including PYSEC, GitHub and GitLab.

- We improved the documentation including adding development examples for importers and improvers.

- We removed the ability to edit relationships from the UI. The UI is now read-only.

- We replace the web UI with a brand new UI based on the same overall look and feel as ScanCode.io.

- We added support for NixOS as a Linux deployment target.

- The aliases of a vulnerabily are reported in the API vulnerabilities/ endpoint

- There are breaking Changes at API level with changes in the data structure:

  - in the /api/vulnerabilities/ endpoint:

    - Rename `resolved_packages` to `fixed_packages` 
    - Rename `unresolved_packages` to `affected_packages`
    - Rename `url` to `reference_url` in the reference list
    - Add is_vulnerable property in fixed and affected_packages.

  - in the /api/packages/ endpoint:

    - Rename `unresolved_vulnerabilities` to `affected_by_vulnerabilities`
    - Rename  `resolved_vulnerabilities` to `fixing_vulnerabilities`
    - Rename `url` to `reference_url` in the reference list
    - Add new attribute `is_resolved`
    - Add namespace filter

- We have provided backward compatibility for `url` and `unresolved_vulnerabilities` for now.
  These will be removed in the next major version and should be considered as deprecated.

- There is a new experimental `cpe/` API endpoint to lookup for vulnerabilities by CPE and 
  another aliases/ endpoint to lookup for vulnerabilities by aliases. These two endpoints will be
  replaced by query parameters on the main vulnerabilities/ endpoint when stabilized.

- Added filters for vulnerabilities endpoint to get fixed packages in accordance
  to the details given in filters: For example, when you call the endpoint this way
  ``/api/vulnerabilities?type=pypi&namespace=foo&name=bar``, you will receive only
  fixed versioned purls of the type ``pypi``, namespace ``foo`` and name ``bar``.

- Package endpoint will give fixed packages of only those that
  matches type, name, namespace, subpath and qualifiers of the package queried.

- Paginated initial listings to display a small number of records 
  and provided page per size with a maximum limit of 100 records per page.

- Add fixed packages in vulnerabilities details in packages endpoint.

- Add bulk search support for CPEs.

- Add authentication for REST API endpoint.
  The autentication is disabled by default and can be enabled using the
  VULNERABLECODEIO_REQUIRE_AUTHENTICATION settings.
  When enabled, users have to authenticate using 
  their API Key in the REST API.
  Users can be created using the Django "createsuperuser" management command.

- The data license is now CC-BY-SA-4.0 as this is the highest common
  denominator license among all the data sources we collect and aggregate. 


Other:

- We dropped calver to use a plain semver.
- We adopted vers and the new univers library to handle version ranges.


Version v20.10
---------------

This release comes with the new calver versioning scheme and an initial data dump.
