Release notes
=============

Version v30.0.0
----------------

- Refactor core processing with Importers that import data and Improvers that
  get the imported data and convert that in Vulnerabilities and Packages and can
  also improve and refine imported and existing data. The migration to this new
  architecture is under way.

- Add new data sources including OSV, GitHub and GitLab.

- Improve documentation including adding examples for importers and improvers

- Remove the ability to edit relationships from the UI. The UI is now read-only
  and we will need to design a different UI for proper review and curation of
  vulnerabilities.

- Add support for nix as a Linux deployment target.

- Lookup vulnerabilities from CPE through API

- Breaking Changes at API level
  - /api/vulnerabilities 
    - Replace `resolved_packages` by `fixed_packages` 
    - Replace `unresolved_packages` by `affected_packages`
    - Replace `url` by `reference_url` in the reference list
  - /api/packages
    - Replace `unresolved_vulnerabilities` by `affected_by_vulnerabilities`
    - Replace  `resolved_vulnerabilities` by `fixing_vulnerabilities`
    - Replace `url` by `reference_url` in the reference list

- Add alias to the /api/vulnerabilities

- Lookup vulnerabilities from aliases



Version v20.10
---------------

This release comes with the new calver versioning scheme and an initial data dump.
