from django.test import TestCase

from vulnerabilities.models import AffectedByPackageRelatedVulnerability
from vulnerabilities.models import CodeFix
from vulnerabilities.models import Package
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import VulnerabilityRelatedReference
from vulnerabilities.pipelines.collect_commits import CollectFixCommitsPipeline
from vulnerabilities.pipelines.collect_commits import is_vcs_url
from vulnerabilities.pipelines.collect_commits import is_vcs_url_already_processed
from vulnerabilities.pipelines.collect_commits import normalize_vcs_url


class CollectFixCommitsPipelineTests(TestCase):
    def setUp(self):
        self.vulnerability = Vulnerability.objects.create(
            vulnerability_id="VCID-1234", summary="Test vulnerability"
        )

        package = Package.objects.create(type="npm", namespace="abc", name="def", version="1")

        self.affected_by_vuln = AffectedByPackageRelatedVulnerability.objects.create(
            package=package, vulnerability=self.vulnerability
        )

        self.reference1 = VulnerabilityReference.objects.create(
            url="https://github.com/example/repo/commit/abcd1234"
        )

        self.reference2 = VulnerabilityReference.objects.create(
            url="https://gitlab.com/example/repo/commit/efgh5678"
        )
        VulnerabilityRelatedReference.objects.create(
            vulnerability=self.vulnerability, reference=self.reference2
        )
        VulnerabilityRelatedReference.objects.create(
            vulnerability=self.vulnerability, reference=self.reference1
        )

    def test_is_vcs_url(self):
        valid_urls = [
            "git://github.com/angular/di.js.git",
            "https://github.com/user/repo.git",
            "git@gitlab.com:user/repo.git",
        ]
        invalid_urls = [
            "ftp://example.com/not-a-repo",
            "random-string",
            "https://example.com/not-a-repo",
        ]
        for url in valid_urls:
            assert is_vcs_url(url) is True

        for url in invalid_urls:
            assert is_vcs_url(url) is False

    def test_normalize_vcs_url(self):

        assert (
            normalize_vcs_url("git@github.com:user/repo.git") == "https://github.com/user/repo.git"
        )
        assert normalize_vcs_url("github:user/repo") == "https://github.com/user/repo"
        assert normalize_vcs_url(
            "https://github.com/user/repo.git"
        ), "https://github.com/user/repo.git"

    def test_is_vcs_url_already_processed(self):
        CodeFix.objects.create(
            commits=["https://github.com/example/repo/commit/abcd1234"],
            affected_package_vulnerability=self.affected_by_vuln,
        )
        assert (
            is_vcs_url_already_processed("https://github.com/example/repo/commit/abcd1234") is True
        )
        assert (
            is_vcs_url_already_processed("https://github.com/example/repo/commit/unknown") is False
        )

    def test_collect_and_store_fix_commits(self):
        pipeline = CollectFixCommitsPipeline()
        pipeline.collect_and_store_fix_commits()

        assert (
            CodeFix.objects.filter(
                commits__contains=["https://github.com/example/repo/commit/abcd1234"]
            ).exists()
            is True
        )
        assert (
            CodeFix.objects.filter(
                commits__contains=["https://gitlab.com/example/repo/commit/efgh5678"]
            ).exists()
            is True
        )

    def test_skip_already_processed_commit(self):
        CodeFix.objects.create(
            commits=["https://github.com/example/repo/commit/abcd1234"],
            affected_package_vulnerability=self.affected_by_vuln,
        )

        pipeline = CollectFixCommitsPipeline()
        pipeline.collect_and_store_fix_commits()

        # Ensure duplicate entry was not created
        self.assertEqual(
            CodeFix.objects.filter(
                commits__contains=["https://github.com/example/repo/commit/abcd1234"]
            ).count(),
            1,
        )


class IsVCSURLTests(TestCase):
    def test_valid_vcs_urls(self):
        valid_urls = [
            "git://github.com/example/repo.git",
            "https://github.com/example/repo.git",
            "git@github.com:example/repo.git",
            "github:user/repo",
        ]
        for url in valid_urls:
            with self.subTest(url=url):
                self.assertTrue(is_vcs_url(url))

    def test_invalid_vcs_urls(self):
        invalid_urls = ["http://example.com", "ftp://example.com/repo", "random-string"]
        for url in invalid_urls:
            with self.subTest(url=url):
                self.assertFalse(is_vcs_url(url))


class NormalizeVCSURLTests(TestCase):
    def test_normalize_valid_vcs_urls(self):
        self.assertEqual(
            normalize_vcs_url("git@github.com:user/repo.git"), "https://github.com/user/repo.git"
        )
        self.assertEqual(normalize_vcs_url("github:user/repo"), "https://github.com/user/repo")
        self.assertEqual(
            normalize_vcs_url("https://github.com/user/repo.git"),
            "https://github.com/user/repo.git",
        )


class IsVCSURLAlreadyProcessedTests(TestCase):
    def setUp(self):
        self.vulnerability = Vulnerability.objects.create(vulnerability_id="VCID-5678")
        package = Package.objects.create(type="npm", namespace="abc", name="def", version="1")
        self.affected_by_vuln = AffectedByPackageRelatedVulnerability.objects.create(
            package=package, vulnerability=self.vulnerability
        )
        self.code_fix = CodeFix.objects.create(
            commits=["https://github.com/example/repo/commit/commit1"],
            affected_package_vulnerability=self.affected_by_vuln,
        )

    def test_commit_already_processed(self):
        self.assertTrue(
            is_vcs_url_already_processed("https://github.com/example/repo/commit/commit1")
        )

    def test_commit_not_processed(self):
        self.assertFalse(
            is_vcs_url_already_processed("https://github.com/example/repo/commit/commit2")
        )
