Release notes
=============


Version v36.1.2
---------------------

- Get tag from VERSION manifest #1895


Version v36.1.1
---------------------

- Update is_active help text in pipeline migration #1887


Version v36.1.0
---------------------

- Remove admin panel #1885
- Support running pipelines in scheduled task queue #1871
- Optimize export management command #1868
- Fix alpine linux importer #1861
- Stop github OSV importer crashes #1854
- Make advisory content_id a unique field #1864


Version v36.0.0
---------------------

- Add indexes for models https://github.com/aboutcode-org/vulnerablecode/pull/1701
- Add fixed by package in V2 API https://github.com/aboutcode-org/vulnerablecode/pull/1706
- Add tests for num queries for views https://github.com/aboutcode-org/vulnerablecode/pull/1730
- Add postgresql conf in docker-compose https://github.com/aboutcode-org/vulnerablecode/pull/1733
- Add default postgresql.conf for local docker build https://github.com/aboutcode-org/vulnerablecode/pull/1735
- Add models for CodeFix https://github.com/aboutcode-org/vulnerablecode/pull/1704
- Migrate Alpine Linux importer to aboutcode pipeline https://github.com/aboutcode-org/vulnerablecode/pull/1737
- VCIO-next: Allow CVSS3.1 Severities in NVD https://github.com/aboutcode-org/vulnerablecode/pull/1738
- Add Pipeline to add missing CVSSV3.1 scores https://github.com/aboutcode-org/vulnerablecode/pull/1740
- Add description and reference to the latest release on the homepage https://github.com/aboutcode-org/vulnerablecode/pull/1743
- Use proper apk package type for Alpine https://github.com/aboutcode-org/vulnerablecode/pull/1739
- Optimize vulnerabilities view https://github.com/aboutcode-org/vulnerablecode/pull/1728
- Add CWE support in multiple importers https://github.com/aboutcode-org/vulnerablecode/pull/1526
- Fast content ID migration https://github.com/aboutcode-org/vulnerablecode/pull/1795
- Add captcha for user signup https://github.com/aboutcode-org/vulnerablecode/pull/1822
- Move the package search box to the top by @keshav-space in https://github.com/aboutcode-org/vulnerablecode/pull/1832


Version v35.1.0
---------------------

- Use AboutCode mirror for collecting CISA KEV #1685
- Do not report ghost package as a fix for vulnerability #1679
- Add pipeline to sort packages #1686
- Fix urls for API #1678


Version v35.0.0
---------------------

- Add scores in bulk search V1 API #1675
- Add improver pipeline to flag ghost packages #644 #917 #1395 by @keshav-space in https://github.com/aboutcode-org/vulnerablecode/pull/1533
- Add base pipeline for importers and migrate PyPa importer to aboutcode pipeline by @keshav-space in https://github.com/aboutcode-org/vulnerablecode/pull/1559
- Remove dupe Package.get_non_vulnerable_versions by @pombredanne in https://github.com/aboutcode-org/vulnerablecode/pull/1570
- Import data from GSD #706 by @ziadhany in https://github.com/aboutcode-org/vulnerablecode/pull/787
- Add curl advisories importer by @ambuj-1211 in https://github.com/aboutcode-org/vulnerablecode/pull/1439
- Update dependencies by @TG1999 in https://github.com/aboutcode-org/vulnerablecode/pull/1590
- Bump django from 4.2.0 to 4.2.15 by @dependabot in https://github.com/aboutcode-org/vulnerablecode/pull/1591
- Bump cryptography from 42.0.4 to 43.0.1 by @dependabot in https://github.com/aboutcode-org/vulnerablecode/pull/1582
- Bump actions/download-artifact from 3 to 4.1.7 in /.github/workflows by @dependabot in https://github.com/aboutcode-org/vulnerablecode/pull/1581
- Improve export command by @pombredanne in https://github.com/aboutcode-org/vulnerablecode/pull/1571
- Fix typo in Kev requests import by @ziadhany in https://github.com/aboutcode-org/vulnerablecode/pull/1594
- Prepare for release v34.0.1 by @TG1999 in https://github.com/aboutcode-org/vulnerablecode/pull/1595
- Bump upload-artifact to v4 by @keshav-space in https://github.com/aboutcode-org/vulnerablecode/pull/1596
- Migrate Npm importer to aboutcode pipeline by @keshav-space in https://github.com/aboutcode-org/vulnerablecode/pull/1574
- Use correct regex for CVE by @pombredanne in https://github.com/aboutcode-org/vulnerablecode/pull/1599
- Migrate Nginx importer to aboutcode pipeline by @keshav-space in https://github.com/aboutcode-org/vulnerablecode/pull/1575
- Migrate GitLab importer to aboutcode pipeline by @keshav-space in https://github.com/aboutcode-org/vulnerablecode/pull/1580
- Migrate GitHub importer to aboutcode pipeline by @keshav-space in https://github.com/aboutcode-org/vulnerablecode/pull/1584
- Migrate NVD importer to aboutcode pipeline by @keshav-space in https://github.com/aboutcode-org/vulnerablecode/pull/1587
- Match affected and fixed-by Packages by @johnmhoran in https://github.com/aboutcode-org/vulnerablecode/pull/1528
- Add management command to commit exported data by @keshav-space in https://github.com/aboutcode-org/vulnerablecode/pull/1600
- Add support to Exploits model by @ziadhany in https://github.com/aboutcode-org/vulnerablecode/pull/1562
- Fix 500 Server Error with DRF browsable API and resolve blank Swagger API documentation by @keshav-space in https://github.com/aboutcode-org/vulnerablecode/pull/1603
- Release v34.0.2 by @TG1999 in https://github.com/aboutcode-org/vulnerablecode/pull/1604
- Bump VCIO version by @TG1999 in https://github.com/aboutcode-org/vulnerablecode/pull/1605
- Bump django from 4.2.15 to 4.2.16 by @dependabot in https://github.com/aboutcode-org/vulnerablecode/pull/1608
- Bump fetchcode from v0.3.0 to v0.6.0 by @keshav-space in https://github.com/aboutcode-org/vulnerablecode/pull/1607
- Use 4-tier system for storing package metadata by @keshav-space in https://github.com/aboutcode-org/vulnerablecode/pull/1609
- Fix vers range crash by @pombredanne in https://github.com/aboutcode-org/vulnerablecode/pull/1598
- Add GitHub action to publish aboutcode.hashid PyPI by @keshav-space in https://github.com/aboutcode-org/vulnerablecode/pull/1615
- Segregate PackageRelatedVulnerability model to new models by @TG1999 in https://github.com/aboutcode-org/vulnerablecode/pull/1612
- Add documentation for new pipeline design by @keshav-space in https://github.com/aboutcode-org/vulnerablecode/pull/1621
- Fix 500 error in /api/cpes endpoint by @keshav-space in https://github.com/aboutcode-org/vulnerablecode/pull/1629
- Migrate pysec importer to aboutcode pipeline by @keshav-space in https://github.com/aboutcode-org/vulnerablecode/pull/1628
- Avoid memory exhaustion during data migration by @keshav-space in https://github.com/aboutcode-org/vulnerablecode/pull/1630
- Add support for Calculating Risk in VulnerableCode by @ziadhany in https://github.com/aboutcode-org/vulnerablecode/pull/1593
- Bulk create in migrations by @TG1999 in https://github.com/aboutcode-org/vulnerablecode/pull/1640
- Update README.rst by @TG1999 in https://github.com/aboutcode-org/vulnerablecode/pull/1641
- Prepare for release v34.1.0 by @TG1999 in https://github.com/aboutcode-org/vulnerablecode/pull/1642
- Add V2 API endpoints by @TG1999 in https://github.com/aboutcode-org/vulnerablecode/pull/1631
- Prepare for release v34.2.0 by @TG1999 in https://github.com/aboutcode-org/vulnerablecode/pull/1647
- Refactor severity score model and fix incorrect suse scores by @keshav-space in https://github.com/aboutcode-org/vulnerablecode/pull/1636
- Add bulk search in v2 by @TG1999 in https://github.com/aboutcode-org/vulnerablecode/pull/1649
- Prepare release v34.3.0 by @TG1999 in https://github.com/aboutcode-org/vulnerablecode/pull/1652
- Add `on_failure` to handle cleanup during pipeline failure by @keshav-space in https://github.com/aboutcode-org/vulnerablecode/pull/1651
- Fix API bug by @TG1999 in https://github.com/aboutcode-org/vulnerablecode/pull/1654
- Add reference score to package endpoint  by @keshav-space in https://github.com/aboutcode-org/vulnerablecode/pull/1655
- Prepare for release v34.3.2 by @TG1999 in https://github.com/aboutcode-org/vulnerablecode/pull/1656
- Add support for storing  exploitability and weighted severity by @ziadhany in https://github.com/aboutcode-org/vulnerablecode/pull/1646
- Avoid migrations on version bumps by @keshav-space in https://github.com/aboutcode-org/vulnerablecode/pull/1660
- Prepare v35.0.0rc1 by @TG1999 in https://github.com/aboutcode-org/vulnerablecode/pull/1664



Version v35.0.0rc1
---------------------

- Add support for storing exploitability and weighted severity #1646
- Avoid migrations on version bumps #1660


Version v34.3.2
----------------

- HOTFIX: Add reference score to package endpoint #1655


Version v34.3.1
----------------

- HOTFIX: Fix API bug #1654


Version v34.3.0
-----------------

- Add bulk search in v2 #1649 
- Refactor severity score model and fix incorrect suse scores #1636


Version v34.2.0
-------------------

- Add V2 API endpoints #1631


Version v34.1.0
-------------------

- Add support for Calculating Package Vulnerability Risk #1593
- Migrate pysec importer to aboutcode pipeline #1628
- Fix 500 error in /api/cpes endpoint #1629
- Add documentation for new pipeline design #1621
- Segregate PackageRelatedVulnerability model to new models #1612
- Add GitHub action to publish aboutcode.hashid PyPI #1615
- Fix vers range crash #1598
- Use 4-tier system for storing package metadata #1609


Version v34.0.2
-------------------

- Add management command to commit exported vulnerability data (#1600)
- Fix API 500 error (#1603)


Version v34.0.1
-------------------

- Add Pipeline to flag ghost packages (#1533)
- Add logging configuration (#1533)
- Drop support for python 3.8 (#1533)
- Drop using docker-compose and use the built-in "docker compose" instead
- Upgrade core dependencies including Django and Rest Framework
- Fix typo in KEV improver (#1594)


Version v34.0.0
-------------------

- Improve API performance.
- Add severity range score in API.
- Refactor GitlabDataSource to work with browser extension


Version v34.0.0rc5
-------------------

- Add safetydb importer.
- Add missing width setting for the table in the vulnerability details UI.
- Add KEV support.
- Add UI template for API.
- Use VersionRange.normalize to compare advisory.
- Use integer column to display score.
- Add support for CVSSv4 & SSVC and import the data using vulnrichment.
- Add support for reference_type in the API.
- Add API improvements for the package endpoint.


Version v34.0.0rc4
-------------------

- Drop migration for removing duplicated changelogs.


Version v34.0.0rc3
-------------------

- Add resource URL to the vulnerability and package details view in the API serializers (#1423)
- Add support for all osv ecosystems (#926)
- Add RubyImporter to git_importer test_git_importer_clone (#799)
- Remove duplicated changelogs (#1400)
- Fix Encoding Type in Fireeye Importer (#1404)
- Add license_url for GitHub Importer (#1392)
- Add support for CVSS vectors display (#1312)


Version v34.0.0rc2
-------------------

- We updated package-url models, WARNING: in next major version of 
  vulnerablecode i.e v35.0.0 qualifiers will be of type ``string`` and not ``dict``.
- We added changelog and dates on packages and vulnerabilities.
- We fixed table borders in Vulnerability details UI #1356 (#1358)
- We added robots.txt in views.
- We fixed import runner's process_inferences (#1360)
- We fixed debian OVAL importer (#1361)
- We added graph model diagrams #977(#1350)
- We added endpoint for purl lookup (#1359)
- We fixed swagger API docs generation (#1366)
- Fix issues https://github.com/nexB/vulnerablecode/issues/1385, https://github.com/nexB/vulnerablecode/issues/1387


Version v34.0.0rc1
-------------------

- We updated package-url models, WARNING: in next major version of 
  vulnerablecode i.e v35.0.0 qualifiers will be of type ``string`` and not ``dict``.
- We added changelog and dates on packages and vulnerabilities.
- We fixed table borders in Vulnerability details UI #1356 (#1358)
- We added robots.txt in views.
- We fixed import runner's process_inferences (#1360)
- We fixed debian OVAL importer (#1361)
- We added graph model diagrams #977(#1350)
- We added endpoint for purl lookup (#1359)
- We fixed swagger API docs generation (#1366)


Version v33.6.5
-------------------

- We added /var/www/html as volume in nginx Docker compose (#1373).


Version v33.6.4
-------------------

- We added /var/www/html as volume in Docker compose (#1371).


Version v33.6.3
----------------

- We updated RTD build configuration.
- We added importer for OSS-Fuzz.
- We removed vulnerabilities with empty aliases.
- We fixed search encoding issue https://github.com/nexB/vulnerablecode/issues/1336.
- We added middleware to ban "bytedance" user-agent.


Version v33.6.2
----------------

- We added note about CSRF_TRUSTED_ORIGINS.
- We added proper acknowledgements for NGI projects.
- We added throttling for anonymous users.

Version v33.6.1
----------------

- We added pagination to valid versions improver.


Version v33.6.0
----------------

- We added support to write packages and vulnerabilities at the time of import.


Version v33.5.0
----------------

- We fixed a text-overflow issue in the Essentials tab of the Vulnerability details template.
- We added clickable links to the Essentials tab of the Vulnerability details template that enable
  the user to navigate to the Fixed by packages tab and the Affected packages tab.
- We fixed severity range issue for handling unknown scores.

Version v33.4.0
----------------

- We added importer specific improvers and removed default improver
  additionally improve recent advisories first.


Version v33.3.0
----------------

- We filtered out the weakness that are not presented in the
  cwe2.database before passing them into the vulnerability details view.


Version v33.2.0
-----------------

- We fixed NVD importer to import the latest data by adding weakness
  in unique content ID for advisories.


Version v33.1.0
-----------------

- We have paginated the default improver and added keyboard interrupt support for import and improve processes.
- We bumped PyYaml to 6.0.1 and saneyaml to 0.6.0 and dropped docker-compose.


Version v33.0.0
-----------------

- We have dropped ``unresolved_vulnerabilities`` from /api/package endpoint API response.
- We have added missing quotes for href values in template.
- We have fixed merge functionality of AffectedPackage.


Version v32.0.1
-----------------

- Clean imported data after import process.


Version v32.0.0
-----------------

- We fixed Apache HTTPD and Apache Kafka importer.
- We removed excessive network calls from Redhat importer.
- Add documentation for version 32.0.0.


Version v32.0.0rc4
-------------------

- We added loading of env for GitHub datasource in vulntotal.
- We fixed import process in github importer in vulnerablecode reported here
  https://github.com/nexB/vulnerablecode/issues/1142.
- We added an improver to get all package versions
  of all ecosystems for a range of affected packages.
- We added documentation for configuring throttling rate for API endpoints.
- We fixed kbmsr2019 importer.
- We added support for conan advisories through gitlab importer.


Version v32.0.0rc3
-------------------

- Add aliases to package endpoint.
- We added Apache HTTPD improver.
- We removed redundant API tests.
- We added fireye vulnerabilities advisories importer.
- We added support for public instance of vulnerablecode in vulntotal.
- We re-enabled support for the Apache Kafka vulnerabilities advisories importer.
- We re-enabled support for the xen vulnerabilities advisories importer.
- We re-enabled support for the istio vulnerabilities advisories importer.
- We re-enabled support for the Ubuntu usn vulnerabilities advisories importer.



Version v32.0.0rc2
--------------------

- We added migration for adding apache tomcat option in severity scoring.


Version v32.0.0rc1
--------------------

- We re-enabled support for the mozilla vulnerabilities advisories importer.
- We re-enabled support for the gentoo vulnerabilities advisories importer.
- We re-enabled support for the istio vulnerabilities advisories importer.
- We re-enabled support for the kbmsr2019 vulnerabilities advisories importer.
- We re-enabled support for the suse score advisories importer.
- We re-enabled support for the elixir security advisories importer.
- We re-enabled support for the apache tomcat security advisories importer.
- We added support for CWE.
- We added migrations to remove corrupted advisories https://github.com/nexB/vulnerablecode/issues/1086.


Version v31.1.1
---------------

- We re-enabled support for the Apache HTTPD security advisories importer.
- We now support incomplete versions for a valid purl in search. For example,
  you can now search for ``pkg:nginx/nginx@1`` and get all versions of nginx
  starting with ``1``.


Version v31.1.0
----------------

- We re-enabled support for the NPM vulnerabilities advisories importer.
- We re-enabled support for the Retiredotnet vulnerabilities advisories importer.
- We are now handling purl fragments in package search. For example:
  you can now serch using queries in the UI like this : ``cherrypy@2.1.1``,
  ``cherrypy`` or ``pkg:pypi``.
- We are now ingesting npm advisories data through GitHub API.


Version v31.0.0
----------------

- We added a new Vulntotal command line tool that can compare the vulnerabilities
  between multiple vulnerability databases.

- We refactored how we handle CVSS scores. We are no longer storing a CVSS
  score separately from a CVSS vector. Instead the vector is stored in the
  scoring_elements field.

- We re-enabled support for the PostgreSQL securities advisories importer.

- We fixed the API key request form UI and made it consistent with rest of UI.

- We made bulk search faster by pre-computing `package_url` and
  `plain_package_url` in Package model.  And provided two options in package
  bulk search  ``purl_only`` option to get only vulnerable purls without any
  extra details, ``plain_purl`` option to filter purls without qualifiers and
  subpath and also return them without qualifiers and subpath. The names used
  are provisional and may be updated in a future release.


Version v30.3.1
----------------

This is a minor bug fix release.

- We enabled proper CSRF configuration for deployments


Version v30.3.0
----------------

This is a feature update release including minor bug fixes and the introduction
of API keys and API throttling.

- We enabled API throttling for a basic user and for a staff user
  they can have unlimited access on API.

- We added throttle rate for each API endpoint and it can be
  configured from the settings #991 https://github.com/nexB/vulnerablecode/issues/991

- We improved how we import NVD data
- We refactored and made the purl2cpe script work to dump purl to CPE mappings

Internally:

- We aligned key names internally with the names used in the UI and API (such as affected and fixed)
- We now use querysets as model managers and have streamlined view code


Version v30.2.1
----------------

- We refactored and fixed the LaunchPad API code.
- We now ignore qualifiers and subpath from PURL search lookups.
- We fixed severity table column spillover.


Version v30.2.0
----------------

This is a critical bug fix release including features updates.

- We fixed critical performance issues that made the web UI unusable. This include
  removing some less interesting redundant details displayed in the web UI for
  vulnerabilities.
- We made minor documentation updates.
- We re-enabled support for Arch linux, Debian, and Ubuntu security advisories importers
- We added a new improver for Oval data sources
- We improved Alpine linux and Gitlab security advisories importers

The summary of performance improvements include these fixes:

- Cascade queries from exact to approximate searches to avoid full table scans
  in all cases. This is a band-aid for now. The proper solution will likely
  require using full text search instead.
- Avoid iceberg queries with "prefetch related" to limit the number of queries
  that are needed in the UI
- Do not recreate querysets from scratch but instead allow these to be chained
  for simpler and correct code.
- Remove extra details from the vulnerability pacge: each package was further
  listing its related vulnerabilities creating an iceberg query.
- Enable the django-debug-toolbar with a setting to easily profile queries on demand
  by setting both VULNERABLECODE_DEBUG and VULNERABLECODE_DEBUG_TOOLBAR enviroment
  variables.


Version v30.1.1
----------------

- We added a new web UI link to explain how to obtain an API for the publicly
  hosted VulnerableCode


Version v30.1.0
----------------

- We added a new "/packages/all" API endpoint to get all Package URLs know to be vulnerable.


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

- We replaced the web UI with a brand new UI based on the same overall look and feel as ScanCode.io.

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

- We added filters for vulnerabilities endpoint to get fixed packages in accordance
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
