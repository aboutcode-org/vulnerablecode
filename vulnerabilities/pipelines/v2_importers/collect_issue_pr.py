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
    pipeline_id = "collect-busybox-prs-issues"
    repo_url = "https://github.com/mirror/busybox"


class CollectNginxPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect-nginx-prs-issues"
    repo_url = "https://github.com/nginx/nginx"


class CollectApacheTomcatPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect-apache-tomcat-prs-issues"
    repo_url = "https://github.com/apache/tomcat"


class CollectMongodbPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect-mongodb-prs-issues"
    repo_url = "https://github.com/mongodb/mongo"


class CollectRedisPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect-redis-prs-issues"
    repo_url = "https://github.com/redis/redis"


class CollectPhpPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect-php-prs-issues"
    repo_url = "https://github.com/php/php-src"


class CollectPythonCpythonPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect-python-cpython-prs-issues"
    repo_url = "https://github.com/python/cpython"


class CollectRubyPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect-ruby-prs-issues"
    repo_url = "https://github.com/ruby/ruby"


class CollectGoPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect-go-prs-issues"
    repo_url = "https://github.com/golang/go"


class CollectNodeJsPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect-node-js-prs-issues"
    repo_url = "https://github.com/nodejs/node"


class CollectRustPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect-rust-prs-issues"
    repo_url = "https://github.com/rust-lang/rust"


class CollectOpenjdkPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect-openjdk-prs-issues"
    repo_url = "https://github.com/openjdk/jdk"


class CollectSwiftPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect-swift-prs-issues"
    repo_url = "https://github.com/swiftlang/swift"


class CollectDjangoPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect-django-prs-issues"
    repo_url = "https://github.com/django/django"


class CollectRailsPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect-rails-prs-issues"
    repo_url = "https://github.com/rails/rails"


class CollectLaravelPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect-laravel-prs-issues"
    repo_url = "https://github.com/laravel/framework"


class CollectSpringFrameworkPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect-spring-framework-prs-issues"
    repo_url = "https://github.com/spring-projects/spring-framework"


class CollectReactPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect-react-prs-issues"
    repo_url = "https://github.com/facebook/react"


class CollectAngularPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect-angular-prs-issues"
    repo_url = "https://github.com/angular/angular"


class CollectDockerMobyPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect-docker-moby-prs-issues"
    repo_url = "https://github.com/moby/moby"


class CollectKubernetesPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect-kubernetes-prs-issues"
    repo_url = "https://github.com/kubernetes/kubernetes"


class CollectContainerdPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect-containerd-prs-issues"
    repo_url = "https://github.com/containerd/containerd"


class CollectAnsiblePRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect-ansible-prs-issues"
    repo_url = "https://github.com/ansible/ansible"


class CollectTerraformPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect-terraform-prs-issues"
    repo_url = "https://github.com/hashicorp/terraform"


class CollectTcpdumpPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect-tcpdump-prs-issues"
    repo_url = "https://github.com/the-tcpdump-group/tcpdump"


class CollectJenkinsPRSIssuesPipeline(GitHubCollector):
    pipeline_id = "collect-jenkins_prs-issues"
    repo_url = "https://github.com/jenkinsci/jenkins"


class CollectGitlabPRSIssuesPipeline(GitLabCollector):
    pipeline_id = "collect-gitlab-prs-issues"
    repo_url = "https://gitlab.com/gitlab-org/gitlab-foss"


class CollectWiresharkPRSIssuesPipeline(GitLabCollector):
    pipeline_id = "collect-wireshark-prs-issues"
    repo_url = "https://gitlab.com/wireshark/wireshark"


class CollectQemuPRSIssuesPipeline(GitLabCollector):
    pipeline_id = "collect-qemu-prs-issues"
    repo_url = "https://gitlab.com/qemu-project/qemu"
