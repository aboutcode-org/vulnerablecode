from vulnerabilities.pipelines import CollectVCSFixCommitPipeline


class CollectLinuxFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_linux_fix_commits"
    repo_url = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"


class CollectBusyBoxFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_busybox_fix_commits"
    repo_url = "https://github.com/mirror/busybox.git"


class CollectNginxFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_nginx_fix_commits"
    repo_url = "https://github.com/nginx/nginx.git"


class CollectApacheTomcatFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_apache_tomcat_fix_commits"
    repo_url = "https://github.com/apache/tomcat.git"


class CollectMysqlServerFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_mysql_server_fix_commits"
    repo_url = "https://github.com/mysql/mysql-server.git"


class CollectPostgresqlFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_postgresql_fix_commits"
    repo_url = "https://github.com/postgres/postgres.git"


class CollectMongodbFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_mongodb_fix_commits"
    repo_url = "https://github.com/mongodb/mongo.git"


class CollectRedisFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_redis_fix_commits"
    repo_url = "https://github.com/redis/redis.git"


class CollectSqliteFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_sqlite_fix_commits"
    repo_url = "https://github.com/sqlite/sqlite.git"


class CollectPhpFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_php_fix_commits"
    repo_url = "https://github.com/php/php-src.git"


class CollectPythonCpythonFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_python_cpython_fix_commits"
    repo_url = "https://github.com/python/cpython.git"


class CollectRubyFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_ruby_fix_commits"
    repo_url = "https://github.com/ruby/ruby.git"


class CollectGoFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_go_fix_commits"
    repo_url = "https://github.com/golang/go.git"


class CollectNodeJsFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_node_js_fix_commits"
    repo_url = "https://github.com/nodejs/node.git"


class CollectRustFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_rust_fix_commits"
    repo_url = "https://github.com/rust-lang/rust.git"


class CollectOpenjdkFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_openjdk_fix_commits"
    repo_url = "https://github.com/openjdk/jdk.git"


class CollectSwiftFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_swift_fix_commits"
    repo_url = "https://github.com/swiftlang/swift.git"


class CollectOpensslFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_openssl_fix_commits"
    repo_url = "https://github.com/openssl/openssl.git"


class CollectDjangoFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_django_fix_commits"
    repo_url = "https://github.com/django/django.git"


class CollectRailsFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_rails_fix_commits"
    repo_url = "https://github.com/rails/rails.git"


class CollectLaravelFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_laravel_fix_commits"
    repo_url = "https://github.com/laravel/framework.git"


class CollectSpringFrameworkFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_spring_framework_fix_commits"
    repo_url = "https://github.com/spring-projects/spring-framework.git"


class CollectReactFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_react_fix_commits"
    repo_url = "https://github.com/facebook/react.git"


class CollectAngularFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_angular_fix_commits"
    repo_url = "https://github.com/angular/angular.git"


class CollectWordpressFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_wordpress_fix_commits"
    repo_url = "https://github.com/WordPress/WordPress.git"


class CollectDockerMobyFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_docker_moby_fix_commits"
    repo_url = "https://github.com/moby/moby.git"


class CollectKubernetesFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_kubernetes_fix_commits"
    repo_url = "https://github.com/kubernetes/kubernetes.git"


class CollectQemuFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_qemu_fix_commits"
    repo_url = "https://gitlab.com/qemu-project/qemu.git"


class CollectXenProjectFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_xen_project_fix_commits"
    repo_url = "https://github.com/xen-project/xen.git"


class CollectVirtualboxFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_virtualbox_fix_commits"
    repo_url = "https://github.com/mirror/vbox.git"


class CollectContainerdFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_containerd_fix_commits"
    repo_url = "https://github.com/containerd/containerd.git"


class CollectAnsibleFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_ansible_fix_commits"
    repo_url = "https://github.com/ansible/ansible.git"


class CollectTerraformFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_terraform_fix_commits"
    repo_url = "https://github.com/hashicorp/terraform.git"


class CollectWiresharkFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_wireshark_fix_commits"
    repo_url = "https://gitlab.com/wireshark/wireshark.git"


class CollectTcpdumpFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_tcpdump_fix_commits"
    repo_url = "https://github.com/the-tcpdump-group/tcpdump.git"


class CollectGitFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_git_fix_commits"
    repo_url = "https://github.com/git/git.git"


class CollectJenkinsFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_jenkins_fix_commits"
    repo_url = "https://github.com/jenkinsci/jenkins.git"


class CollectGitlabFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_gitlab_fix_commits"
    repo_url = "https://gitlab.com/gitlab-org/gitlab-foss.git"
