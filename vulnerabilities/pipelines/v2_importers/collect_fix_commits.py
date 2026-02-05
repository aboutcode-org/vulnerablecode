from vulnerabilities.pipes.vcs_collector_utils import CollectVCSFixCommitPipeline


class CollectLinuxFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_linux_fix_commits"
    repo_url = "https://github.com/torvalds/linux"


class CollectBusyBoxFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_busybox_fix_commits"
    repo_url = "https://github.com/mirror/busybox"


class CollectNginxFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_nginx_fix_commits"
    repo_url = "https://github.com/nginx/nginx"


class CollectApacheTomcatFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_apache_tomcat_fix_commits"
    repo_url = "https://github.com/apache/tomcat"


class CollectMysqlServerFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_mysql_server_fix_commits"
    repo_url = "https://github.com/mysql/mysql-server"


class CollectPostgresqlFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_postgresql_fix_commits"
    repo_url = "https://github.com/postgres/postgres"


class CollectMongodbFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_mongodb_fix_commits"
    repo_url = "https://github.com/mongodb/mongo"


class CollectRedisFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_redis_fix_commits"
    repo_url = "https://github.com/redis/redis"


class CollectSqliteFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_sqlite_fix_commits"
    repo_url = "https://github.com/sqlite/sqlite"


class CollectPhpFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_php_fix_commits"
    repo_url = "https://github.com/php/php-src"


class CollectPythonCpythonFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_python_cpython_fix_commits"
    repo_url = "https://github.com/python/cpython"


class CollectRubyFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_ruby_fix_commits"
    repo_url = "https://github.com/ruby/ruby"


class CollectGoFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_go_fix_commits"
    repo_url = "https://github.com/golang/go"


class CollectNodeJsFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_node_js_fix_commits"
    repo_url = "https://github.com/nodejs/node"


class CollectRustFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_rust_fix_commits"
    repo_url = "https://github.com/rust-lang/rust"


class CollectOpenjdkFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_openjdk_fix_commits"
    repo_url = "https://github.com/openjdk/jdk"


class CollectSwiftFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_swift_fix_commits"
    repo_url = "https://github.com/swiftlang/swift"


class CollectDjangoFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_django_fix_commits"
    repo_url = "https://github.com/django/django"


class CollectRailsFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_rails_fix_commits"
    repo_url = "https://github.com/rails/rails"


class CollectLaravelFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_laravel_fix_commits"
    repo_url = "https://github.com/laravel/framework"


class CollectSpringFrameworkFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_spring_framework_fix_commits"
    repo_url = "https://github.com/spring-projects/spring-framework"


class CollectReactFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_react_fix_commits"
    repo_url = "https://github.com/facebook/react"


class CollectAngularFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_angular_fix_commits"
    repo_url = "https://github.com/angular/angular"


class CollectWordpressFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_wordpress_fix_commits"
    repo_url = "https://github.com/WordPress/WordPress"


class CollectDockerMobyFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_docker_moby_fix_commits"
    repo_url = "https://github.com/moby/moby"


class CollectKubernetesFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_kubernetes_fix_commits"
    repo_url = "https://github.com/kubernetes/kubernetes"


class CollectQemuFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_qemu_fix_commits"
    repo_url = "https://gitlab.com/qemu-project/qemu"


class CollectXenProjectFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_xen_project_fix_commits"
    repo_url = "https://github.com/xen-project/xen"


class CollectVirtualboxFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_virtualbox_fix_commits"
    repo_url = "https://github.com/mirror/vbox"


class CollectContainerdFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_containerd_fix_commits"
    repo_url = "https://github.com/containerd/containerd"


class CollectAnsibleFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_ansible_fix_commits"
    repo_url = "https://github.com/ansible/ansible"


class CollectTerraformFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_terraform_fix_commits"
    repo_url = "https://github.com/hashicorp/terraform"


class CollectWiresharkFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_wireshark_fix_commits"
    repo_url = "https://gitlab.com/wireshark/wireshark"


class CollectTcpdumpFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_tcpdump_fix_commits"
    repo_url = "https://github.com/the-tcpdump-group/tcpdump"


class CollectGitFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_git_fix_commits"
    repo_url = "https://github.com/git/git"


class CollectJenkinsFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_jenkins_fix_commits"
    repo_url = "https://github.com/jenkinsci/jenkins"


class CollectGitlabFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_gitlab_fix_commits"
    repo_url = "https://gitlab.com/gitlab-org/gitlab-foss"
