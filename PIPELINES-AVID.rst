.. _pipeline_avid_mapping:

Pipelines AVID Mapping
=========================

- An ``advisory`` represents data obtained from an upstream source and
  transformed into structured data that describes a known vulnerability.

  Each advisory has an upstream Advisory ID (for example,
  ``CVE-2026-23918`` or ``GHSA-6xcx-gx7r-rccj``) that uniquely identifies it
  within its datasource.

- An ``AVID`` is the unique identifier for the datasource used for this
  advisory (datasource_id example: ``nvd`` or ``github_osv``).

  A pipeline AVID is constructed by combining the pipeline identifier with the
  upstream Advisory ID ``datasource_id/advisory_id``. For example:

.. code-block:: text

   github_osv/GHSA-6xcx-gx7r-rccj
   nvd/CVE-2026-23918

The following table describes how each pipeline constructs its AVID.

.. list-table:: Pipeline AVID Mapping
   :header-rows: 1
   :widths: 30 30 40

   * - pipeline name
     - datasource_id
     - advisory_id
   * - archlinux_importer_v2
     - archlinux
     - AVG ID of the record
   * - apache_kafka_importer_v2
     - apache_kafka
     - CVE ID of the record
   * - nvd_importer_v2
     - nvd
     - CVE ID of the record
   * - elixir_security_importer_v2
     - elixir_security
     - {package_name}/{file_id}
   * - npm_importer_v2
     - npm
     - NPM-<ID>
   * - vulnrichment_importer_v2
     - vulnrichment
     - CVE ID of the record
   * - apache_httpd_importer_v2
     - apache_httpd
     - CVE ID of the record
   * - pypa_importer_v2
     - pypa
     - {package_name}/{ID of the OSV record}
   * - gitlab_importer_v2
     - gitlab
     - Identifier of the GitLab community advisory record
   * - pysec_importer_v2
     - pysec
     - ID of the OSV record
   * - xen_importer_v2
     - xen
     - XSA-<ID>
   * - curl_importer_v2
     - curl
     - CURL-CVE ID of the record
   * - oss_fuzz_v2
     - oss_fuzz
     - ID of the OSV record
   * - istio_importer_v2
     - istio
     - ISTIO-SECURITY-<ID>
   * - postgresql_importer_v2
     - postgresql
     - CVE ID of the record
   * - mozilla_importer_v2
     - mozilla
     - MFSA-<ID>
   * - github_osv_importer_v2
     - github_osv
     - ID of the OSV record
   * - redhat_importer_v2
     - redhat
     - RHSA ID of the record
   * - aosp_importer_v2
     - aosp_dataset
     - CVE ID of the record
   * - project_kb_statements_importer_v2
     - project-kb-statements_v2
     - CVE ID of the record
   * - project_kb_msr2019_importer_v2
     - project_kb_msr2019
     - CVE ID of the record
   * - ruby_importer_v2
     - ruby_advisory_db
     - {file_id}
   * - epss_importer_v2
     - epss
     - CVE ID of the record
   * - gentoo_importer_v2
     - gentoo
     - GLSA ID of the record
   * - nginx_importer_v2
     - nginx
     - First alias of the record
   * - debian_importer_v2
     - debian
     - {package_name}/{debian_record_id}
   * - mattermost_importer_v2
     - mattermost
     - MMSA-<ID>
   * - glibc_importer_v2
     - glibc
     - GLIBC-SA-<ID>
   * - apache_tomcat_importer_v2
     - apache_tomcat
     - {page_id}/{cve_id}
   * - suse_score_importer_v2
     - suse_score
     - CVE ID of the record
   * - retiredotnet_importer_v2
     - retiredotnet
     - retiredotnet-{file_id}
   * - ubuntu_osv_importer_v2
     - ubuntu_osv
     - ID of the OSV record
   * - alpine_linux_importer_v2
     - alpine
     - {package_name}/{distroversion}/{version}/{vulnerability_id}
   * - linux_kernel_importer_v2
     - linux_kernel
     - CVE ID of the record
   * - openssl_importer_v2
     - openssl
     - CVE ID of the record
   * - fireeye_importer_v2
     - fireeye
     - {file_id}
   * - collect_{repo_name}_fix_commits
     - {repo_name}_fix_commits
     - CVE ID / GHSA ID of the record
