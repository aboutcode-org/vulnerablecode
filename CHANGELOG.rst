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

- Lookup vulnerabilities from CPE



Version v20.10
---------------

This release comes with the new calver versioning scheme and an initial data dump.
