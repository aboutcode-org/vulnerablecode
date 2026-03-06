#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from vulnerabilities.pipelines import GitHubCollector
from vulnerabilities.pipelines import GitLabCollector


class CollectBusyBoxPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_busybox_prs-issues"
    repo_url = "https://github.com/mirror/busybox"


class CollectNginxPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_nginx_prs-issues"
    repo_url = "https://github.com/nginx/nginx"


class CollectApacheTomcatPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_apache_tomcat_prs-issues"
    repo_url = "https://github.com/apache/tomcat"


class CollectMongodbPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_mongodb_prs-issues"
    repo_url = "https://github.com/mongodb/mongo"


class CollectRedisPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_redis_prs-issues"
    repo_url = "https://github.com/redis/redis"


class CollectPhpPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_php_prs-issues"
    repo_url = "https://github.com/php/php-src"


class CollectPythonCpythonPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_python_cpython_prs-issues"
    repo_url = "https://github.com/python/cpython"


class CollectRubyPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_ruby_prs-issues"
    repo_url = "https://github.com/ruby/ruby"


class CollectGoPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_go_prs-issues"
    repo_url = "https://github.com/golang/go"


class CollectNodeJsPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_node_js_prs-issues"
    repo_url = "https://github.com/nodejs/node"


class CollectRustPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_rust_prs-issues"
    repo_url = "https://github.com/rust-lang/rust"


class CollectOpenjdkPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_openjdk_prs-issues"
    repo_url = "https://github.com/openjdk/jdk"


class CollectSwiftPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_swift_prs-issues"
    repo_url = "https://github.com/swiftlang/swift"


class CollectDjangoPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_django_prs-issues"
    repo_url = "https://github.com/django/django"


class CollectRailsPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_rails_prs-issues"
    repo_url = "https://github.com/rails/rails"


class CollectLaravelPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_laravel_prs-issues"
    repo_url = "https://github.com/laravel/framework"


class CollectSpringFrameworkPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_spring_framework_prs-issues"
    repo_url = "https://github.com/spring-projects/spring-framework"


class CollectReactPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_react_prs-issues"
    repo_url = "https://github.com/facebook/react"


class CollectAngularPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_angular_prs-issues"
    repo_url = "https://github.com/angular/angular"


class CollectWordpressPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_wordpress_prs-issues"
    repo_url = "https://github.com/WordPress/WordPress"


class CollectDockerMobyPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_docker_moby_prs-issues"
    repo_url = "https://github.com/moby/moby"


class CollectKubernetesPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_kubernetes_prs-issues"
    repo_url = "https://github.com/kubernetes/kubernetes"


class CollectXenProjectPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_xen_project_prs-issues"
    repo_url = "https://github.com/xen-project/xen"


class CollectVirtualboxPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_virtualbox_prs-issues"
    repo_url = "https://github.com/mirror/vbox"


class CollectContainerdPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_containerd_prs-issues"
    repo_url = "https://github.com/containerd/containerd"


class CollectAnsiblePRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_ansible_prs-issues"
    repo_url = "https://github.com/ansible/ansible"


class CollectTerraformPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_terraform_prs-issues"
    repo_url = "https://github.com/hashicorp/terraform"


class CollectTcpdumpPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_tcpdump_prs-issues"
    repo_url = "https://github.com/the-tcpdump-group/tcpdump"


class CollectJenkinsPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect_jenkins_prs-issues"
    repo_url = "https://github.com/jenkinsci/jenkins"


class CollectGitlabPRSIssuesPipeline(GitLabCollector):
    pipeline_id = "collect_gitlab_prs-issues"
    repo_url = "https://gitlab.com/gitlab-org/gitlab-foss"


class CollectWiresharkPRSIssuesPipeline(GitLabCollector):
    pipeline_id = "collect_wireshark_prs-issues"
    repo_url = "https://gitlab.com/wireshark/wireshark"


class CollectQemuPRSIssuesPipeline(GitLabCollector):
    pipeline_id = "collect_qemu_prs-issues"
    repo_url = "https://gitlab.com/qemu-project/qemu"
