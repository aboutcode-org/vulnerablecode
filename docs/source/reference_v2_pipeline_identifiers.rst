.. _v2-pipeline-identifiers:

V2 Pipeline Identifiers
=======================

This page documents the ``pipeline_id`` values used by V2 importers and V2 improvers.

Use these identifiers with the Django management commands:

.. code-block:: bash

    ./manage.py import <pipeline_id>
    ./manage.py improve <pipeline_id>

To list what is currently available in your environment:

.. code-block:: bash

    ./manage.py import --list
    ./manage.py improve --list


V2 Importers
------------

The following V2 importer pipeline identifiers are registered in
``vulnerabilities/importers/__init__.py``.

- ``alpine_linux_importer_v2``
- ``aosp_dataset_fix_commits``
- ``apache_httpd_importer_v2``
- ``apache_kafka_importer_v2``
- ``apache_tomcat_importer_v2``
- ``archlinux_importer_v2``
- ``curl_importer_v2``
- ``debian_importer_v2``
- ``elixir_security_importer_v2``
- ``epss_importer_v2``
- ``fireeye_importer_v2``
- ``gentoo_importer_v2``
- ``github_osv_importer_v2``
- ``gitlab_importer_v2``
- ``istio_importer_v2``
- ``mattermost_importer_v2``
- ``mozilla_importer_v2``
- ``nginx_importer_v2``
- ``nodejs_security_wg``
- ``nvd_importer_v2``
- ``openssl_importer_v2``
- ``oss_fuzz_importer_v2``
- ``postgresql_importer_v2``
- ``project-kb-msr-2019_v2``
- ``project-kb-statements_v2``
- ``pypa_importer_v2``
- ``pysec_importer_v2``
- ``redhat_importer_v2``
- ``retiredotnet_importer_v2``
- ``ruby_importer_v2``
- ``suse_importer_v2``
- ``ubuntu_osv_importer_v2``
- ``vulnrichment_importer_v2``
- ``xen_importer_v2``


V2 Fix Commit Collection Importers
----------------------------------

These V2 importers are also registered in ``vulnerabilities/importers/__init__.py``.
They collect fix commit references for specific upstream repositories.

- ``collect_linux_fix_commits``
- ``collect_busybox_fix_commits``
- ``collect_nginx_fix_commits``
- ``collect_apache_tomcat_fix_commits``
- ``collect_mysql_server_fix_commits``
- ``collect_postgresql_fix_commits``
- ``collect_mongodb_fix_commits``
- ``collect_redis_fix_commits``
- ``collect_sqlite_fix_commits``
- ``collect_php_fix_commits``
- ``collect_python_cpython_fix_commits``
- ``collect_ruby_fix_commits``
- ``collect_go_fix_commits``
- ``collect_node_js_fix_commits``
- ``collect_rust_fix_commits``
- ``collect_openjdk_fix_commits``
- ``collect_swift_fix_commits``
- ``collect_django_fix_commits``
- ``collect_rails_fix_commits``
- ``collect_laravel_fix_commits``
- ``collect_spring_framework_fix_commits``
- ``collect_react_fix_commits``
- ``collect_angular_fix_commits``
- ``collect_wordpress_fix_commits``
- ``collect_docker_moby_fix_commits``
- ``collect_kubernetes_fix_commits``
- ``collect_qemu_fix_commits``
- ``collect_xen_project_fix_commits``
- ``collect_virtualbox_fix_commits``
- ``collect_containerd_fix_commits``
- ``collect_ansible_fix_commits``
- ``collect_terraform_fix_commits``
- ``collect_wireshark_fix_commits``
- ``collect_tcpdump_fix_commits``
- ``collect_git_fix_commits``
- ``collect_jenkins_fix_commits``
- ``collect_gitlab_fix_commits``


V2 Improvers
------------

The following V2 improver pipeline identifiers are registered in
``vulnerabilities/improvers/__init__.py``.

- ``collect_ssvc_trees``
- ``compute_advisory_todo_v2``
- ``compute_package_risk_v2``
- ``compute_version_rank_v2``
- ``enhance_with_exploitdb_v2``
- ``enhance_with_kev_v2``
- ``enhance_with_metasploit_v2``
- ``flag_ghost_packages_v2``
- ``relate_severities_v2``
- ``unfurl_version_range_v2``


V2 Improvers Defined In Code
----------------------------

The following V2 improver currently exists in ``vulnerabilities/pipelines/v2_improvers``
but is not listed in the improver registry at the time of writing.

- ``collect_fix_commits_v2``