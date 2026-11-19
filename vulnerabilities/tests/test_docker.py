#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
DOCKERFILE = ROOT_DIR / "Dockerfile"
DOCKERIGNORE = ROOT_DIR / ".dockerignore"
DOCKER_ENV = ROOT_DIR / "docker.env"
DOCKER_COMPOSE = ROOT_DIR / "docker-compose.yml"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_dockerfile_instructions(dockerfile_path):
    """
    Return a list of (instruction, arguments) tuples from a Dockerfile,
    ignoring blank lines and comments.
    """
    instructions = []
    with open(dockerfile_path) as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if parts:
                instructions.append((parts[0].upper(), parts[1] if len(parts) > 1 else ""))
    return instructions


def docker_is_available():
    return shutil.which("docker") is not None


# ---------------------------------------------------------------------------
# Dockerfile structure tests (no Docker daemon required)
# ---------------------------------------------------------------------------


class TestDockerfileStructure:
    def test_dockerfile_exists(self):
        assert DOCKERFILE.exists(), "Dockerfile is missing from the project root"

    def test_dockerignore_exists(self):
        assert DOCKERIGNORE.exists(), ".dockerignore is missing from the project root"

    def test_docker_env_exists(self):
        assert DOCKER_ENV.exists(), "docker.env is missing from the project root"

    def test_docker_compose_exists(self):
        assert DOCKER_COMPOSE.exists(), "docker-compose.yml is missing from the project root"

    def test_base_image_is_python_312(self):
        instructions = parse_dockerfile_instructions(DOCKERFILE)
        from_instructions = [args for inst, args in instructions if inst == "FROM"]
        assert from_instructions, "Dockerfile has no FROM instruction"
        # The base image must use the official python:3.12 Debian image so that
        # the production environment is reproducible.
        assert from_instructions[0].startswith(
            "python:3.12"
        ), f"Expected base image python:3.12, got: {from_instructions[0]!r}"

    def test_workdir_is_app(self):
        instructions = parse_dockerfile_instructions(DOCKERFILE)
        workdirs = [args for inst, args in instructions if inst == "WORKDIR"]
        assert workdirs, "Dockerfile sets no WORKDIR"
        assert workdirs[0] == "/app", f"Expected WORKDIR /app, got: {workdirs[0]!r}"

    def test_pythonunbuffered_env_is_set(self):
        instructions = parse_dockerfile_instructions(DOCKERFILE)
        envs = [args for inst, args in instructions if inst == "ENV"]
        combined = " ".join(envs)
        assert "PYTHONUNBUFFERED" in combined, (
            "PYTHONUNBUFFERED must be set so stdout/stderr are flushed without buffering"
        )

    def test_pythondontwritebytecode_env_is_set(self):
        instructions = parse_dockerfile_instructions(DOCKERFILE)
        envs = [args for inst, args in instructions if inst == "ENV"]
        combined = " ".join(envs)
        assert "PYTHONDONTWRITEBYTECODE" in combined, (
            "PYTHONDONTWRITEBYTECODE must be set to avoid writing .pyc files into the image"
        )

    def test_wait_for_it_is_installed(self):
        # wait-for-it is required so the scheduler/worker containers can wait
        # for the web service to become healthy before starting.
        dockerfile_text = DOCKERFILE.read_text()
        assert "wait-for-it" in dockerfile_text, (
            "wait-for-it must be installed via apt in the Dockerfile"
        )

    def test_apt_cache_is_cleaned(self):
        # Keeping apt cache in the image inflates the image size unnecessarily.
        dockerfile_text = DOCKERFILE.read_text()
        assert "apt-get clean" in dockerfile_text, (
            "apt-get clean should be called after apt-get install to reduce image size"
        )
        assert "rm -rf /var/lib/apt/lists/*" in dockerfile_text, (
            "apt lists should be removed after install to reduce image size"
        )

    def test_setup_cfg_and_requirements_are_copied_before_source(self):
        # setup.cfg and requirements.txt must be copied before the full source
        # so that Docker can cache the pip install layer and avoid reinstalling
        # dependencies on every code change.
        instructions = parse_dockerfile_instructions(DOCKERFILE)
        copy_args = [args for inst, args in instructions if inst == "COPY"]
        assert len(copy_args) >= 2, "Expected at least two COPY instructions in Dockerfile"
        # First COPY should include setup.cfg/requirements files, not the whole app.
        first_copy = copy_args[0]
        assert "setup.cfg" in first_copy or "requirements.txt" in first_copy, (
            "First COPY should transfer dependency files (setup.cfg, requirements.txt) "
            "before copying the full application for better layer caching"
        )

    def test_static_dir_is_created(self):
        dockerfile_text = DOCKERFILE.read_text()
        assert "/var/vulnerablecode/static" in dockerfile_text, (
            "The static files directory /var/vulnerablecode/static must be created in the image"
        )

    def test_no_expose_instruction_in_app_dockerfile(self):
        # The Dockerfile itself does not need an EXPOSE instruction because
        # port mapping is handled entirely in docker-compose.yml.  If EXPOSE
        # is added here without a matching compose entry it can mislead users.
        # This test documents the intentional absence.
        instructions = parse_dockerfile_instructions(DOCKERFILE)
        expose_instructions = [args for inst, args in instructions if inst == "EXPOSE"]
        # If EXPOSE is present, it must match the port used in compose (8000).
        for port in expose_instructions:
            assert port.strip() == "8000", (
                f"Unexpected EXPOSE port {port!r}; compose maps port 8000"
            )

    def test_dockerignore_excludes_venv(self):
        dockerignore_text = DOCKERIGNORE.read_text()
        assert "venv" in dockerignore_text, (
            ".dockerignore must exclude the local venv directory to keep the image lean"
        )

    def test_dockerignore_excludes_git_directory(self):
        dockerignore_text = DOCKERIGNORE.read_text()
        assert ".github" in dockerignore_text or ".git" in dockerignore_text, (
            ".dockerignore must exclude .git/.github to prevent leaking repository metadata"
        )

    def test_dockerignore_excludes_egg_info(self):
        dockerignore_text = DOCKERIGNORE.read_text()
        assert ".egg-info" in dockerignore_text, (
            ".dockerignore must exclude *.egg-info build artifacts"
        )


# ---------------------------------------------------------------------------
# docker.env variable tests
# ---------------------------------------------------------------------------


class TestDockerEnvFile:
    def _parse_env(self):
        """Return a dict of key=value pairs from docker.env, ignoring blank/comment lines."""
        env = {}
        for line in DOCKER_ENV.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                env[key.strip()] = value.strip()
        return env

    def test_postgres_db_is_set(self):
        env = self._parse_env()
        assert "POSTGRES_DB" in env, "docker.env must define POSTGRES_DB"
        assert env["POSTGRES_DB"], "POSTGRES_DB must not be empty"

    def test_postgres_user_is_set(self):
        env = self._parse_env()
        assert "POSTGRES_USER" in env, "docker.env must define POSTGRES_USER"
        assert env["POSTGRES_USER"], "POSTGRES_USER must not be empty"

    def test_postgres_password_is_set(self):
        env = self._parse_env()
        assert "POSTGRES_PASSWORD" in env, "docker.env must define POSTGRES_PASSWORD"
        assert env["POSTGRES_PASSWORD"], "POSTGRES_PASSWORD must not be empty"

    def test_db_host_points_to_service_name(self):
        env = self._parse_env()
        assert "VULNERABLECODE_DB_HOST" in env, (
            "docker.env must define VULNERABLECODE_DB_HOST so the app can reach the database"
        )
        # In compose the database service is called "db"; the host must match.
        assert env["VULNERABLECODE_DB_HOST"] == "db", (
            f"VULNERABLECODE_DB_HOST must be 'db' (the compose service name), "
            f"got {env['VULNERABLECODE_DB_HOST']!r}"
        )

    def test_redis_host_points_to_service_name(self):
        env = self._parse_env()
        assert "VULNERABLECODE_REDIS_HOST" in env, (
            "docker.env must define VULNERABLECODE_REDIS_HOST so the worker can reach Redis"
        )
        assert env["VULNERABLECODE_REDIS_HOST"] == "vulnerablecode_redis", (
            f"VULNERABLECODE_REDIS_HOST must be 'vulnerablecode_redis' (the compose service name), "
            f"got {env['VULNERABLECODE_REDIS_HOST']!r}"
        )

    def test_static_root_is_set(self):
        env = self._parse_env()
        assert "VULNERABLECODE_STATIC_ROOT" in env, (
            "docker.env must define VULNERABLECODE_STATIC_ROOT"
        )
        assert env["VULNERABLECODE_STATIC_ROOT"].startswith("/"), (
            "VULNERABLECODE_STATIC_ROOT should be an absolute path inside the container"
        )

    def test_docker_env_file_has_no_secret_key(self):
        # The SECRET_KEY must never be committed to the repository.  It should
        # be injected at runtime via /etc/vulnerablecode/.env or a secrets
        # manager, not baked into docker.env.
        env_text = DOCKER_ENV.read_text()
        assert "SECRET_KEY" not in env_text, (
            "docker.env must not contain SECRET_KEY; provide it via /etc/vulnerablecode/.env "
            "or a runtime secrets injection mechanism"
        )


# ---------------------------------------------------------------------------
# Integration tests (skipped when Docker daemon is not available)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not docker_is_available(), reason="Docker daemon not available")
class TestDockerBuild:
    """
    These tests build the Docker image and run commands inside a container to
    verify that the production image behaves correctly on its Debian base.

    They are intentionally skipped in the standard pytest run (which runs on
    ubuntu-latest without Docker-in-Docker) and are exercised by the dedicated
    docker-tests workflow.
    """

    IMAGE_TAG = "vulnerablecode-test:ci"

    @pytest.fixture(scope="class", autouse=True)
    def build_image(self):
        result = subprocess.run(
            ["docker", "build", "-t", self.IMAGE_TAG, "."],
            cwd=ROOT_DIR,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"docker build failed:\n{result.stdout}\n{result.stderr}"
        )
        yield
        subprocess.run(
            ["docker", "rmi", "-f", self.IMAGE_TAG],
            cwd=ROOT_DIR,
            capture_output=True,
        )

    def _run_in_container(self, command):
        """Run a shell command inside a throwaway container and return the CompletedProcess."""
        return subprocess.run(
            ["docker", "run", "--rm", self.IMAGE_TAG, "sh", "-c", command],
            capture_output=True,
            text=True,
        )

    def test_python_version_is_312(self):
        result = self._run_in_container("python --version")
        assert result.returncode == 0
        assert "3.12" in result.stdout + result.stderr, (
            f"Expected Python 3.12 inside the container, got: {result.stdout + result.stderr}"
        )

    def test_wait_for_it_is_on_path(self):
        result = self._run_in_container("which wait-for-it")
        assert result.returncode == 0, (
            "wait-for-it binary not found in the container PATH; "
            "check that apt-get install wait-for-it succeeded"
        )

    def test_vulnerablecode_package_is_installed(self):
        result = self._run_in_container("python -c 'import vulnerabilities'")
        assert result.returncode == 0, (
            f"Failed to import vulnerabilities package inside the container:\n"
            f"{result.stdout}\n{result.stderr}"
        )

    def test_pythonunbuffered_is_set_in_container(self):
        result = self._run_in_container("printenv PYTHONUNBUFFERED")
        assert result.returncode == 0
        assert result.stdout.strip() == "1", (
            f"PYTHONUNBUFFERED should be '1' inside the container, got: {result.stdout.strip()!r}"
        )

    def test_pythondontwritebytecode_is_set_in_container(self):
        result = self._run_in_container("printenv PYTHONDONTWRITEBYTECODE")
        assert result.returncode == 0
        assert result.stdout.strip() == "1", (
            "PYTHONDONTWRITEBYTECODE should be '1' inside the container, "
            f"got: {result.stdout.strip()!r}"
        )

    def test_workdir_is_app(self):
        result = self._run_in_container("pwd")
        assert result.returncode == 0
        assert result.stdout.strip() == "/app", (
            f"Container working directory should be /app, got: {result.stdout.strip()!r}"
        )

    def test_static_dir_exists_in_container(self):
        result = self._run_in_container("test -d /var/vulnerablecode/static && echo ok")
        assert result.returncode == 0, (
            "/var/vulnerablecode/static directory is missing inside the container"
        )

    def test_no_pyc_files_written(self):
        # With PYTHONDONTWRITEBYTECODE=1 Python must not write .pyc files.
        result = self._run_in_container(
            "python -c 'import vulnerabilities' && "
            "find /app/vulnerabilities -name '*.pyc' | head -1"
        )
        assert result.returncode == 0
        assert result.stdout.strip() == "", (
            "Found .pyc files in the container even though PYTHONDONTWRITEBYTECODE=1 is set"
        )

    def test_manage_py_is_present(self):
        result = self._run_in_container("test -f /app/manage.py && echo ok")
        assert result.returncode == 0, "manage.py is missing from /app inside the container"

    def test_os_is_debian_based(self):
        # The python:3.12 image is Debian-based.  This matters because the
        # CI test environment uses ubuntu-latest and the two can diverge (e.g.
        # different glibc versions, different default locale).
        result = self._run_in_container("cat /etc/os-release")
        assert result.returncode == 0
        os_info = result.stdout.lower()
        assert "debian" in os_info or "bookworm" in os_info or "bullseye" in os_info, (
            f"Expected a Debian-based OS inside the container, got:\n{result.stdout}"
        )
