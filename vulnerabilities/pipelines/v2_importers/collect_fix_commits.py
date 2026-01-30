from vulnerabilities.pipelines import CollectVCSFixCommitPipeline


class CollectNodejsFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_nodejs_fix_commits"
    repo_url = "https://github.com/nodejs/node"


class CollectCpythonFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_cpython_fix_commits"
    repo_url = "https://github.com/python/cpython"


class CollectGoFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_go_fix_commits"
    repo_url = "https://github.com/golang/go"


class CollectRustFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_rust_lang_fix_commits"
    repo_url = "https://github.com/rust-lang/rust"


class CollectPhpFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_php_fix_commits"
    repo_url = "https://github.com/php/php-src"


class CollectRubyFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_ruby_fix_commits"
    repo_url = "https://github.com/ruby/ruby"


class CollectNginxFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_nginx_fix_commits"
    repo_url = "https://github.com/nginx/nginx"


class CollectPostgresFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_postgres_fix_commits"
    repo_url = "https://github.com/postgres/postgres"


class CollectMysqlFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_mysql_fix_commits"
    repo_url = "https://github.com/mysql/mysql-server"


class CollectGitFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_git_fix_commits"
    repo_url = "https://github.com/git/git"


class CollectTensorflowFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_tensorflow_fix_commits"
    repo_url = "https://github.com/tensorflow/tensorflow"


class CollectFirefoxFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_firefox_fix_commits"
    repo_url = "https://github.com/mozilla-firefox/firefox"


class CollectQEMUFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_qemu_fix_commits"
    repo_url = "https://github.com/qemu/qemu"


class CollectDenoFixCommitsPipeline(CollectVCSFixCommitPipeline):
    pipeline_id = "collect_deno_fix_commits"
    repo_url = "https://github.com/denoland/deno"
