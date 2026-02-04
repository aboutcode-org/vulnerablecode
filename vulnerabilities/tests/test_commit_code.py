from datetime import datetime

import pytest
from django.core.exceptions import ValidationError

from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import ImpactedPackage
from vulnerabilities.models import PackageCommitPatch


@pytest.mark.django_db
class TestCodePatch:
    def setup_method(self):
        date = datetime.now()
        adv = AdvisoryV2.objects.create(
            unique_content_id="test_id",
            url="https://example.com",
            summary="summary",
            date_collected=date,
            advisory_id="test_id",
            avid="test_pipeline/test_id",
            datasource_id="test_pipeline",
        )

        self.impacted = ImpactedPackage.objects.create(
            advisory=adv,
            base_purl="pkg:pypi/redis",
        )

        self.pkg_commit_patch1 = PackageCommitPatch.objects.create(
            commit_hash="8c001a11dbcb3eb6d851e18f4cefa080af5fb398",
            vcs_url="https://github.com/aboutcode-org/test1/",
            patch_text="test1",
        )

        self.pkg_commit_patch2 = PackageCommitPatch.objects.create(
            commit_hash="8c001a1",
            vcs_url="https://github.com/aboutcode-org/test1/",
        )

        self.impacted.fixed_by_package_commit_patches.add(self.pkg_commit_patch1)
        self.impacted.introduced_by_package_commit_patches.add(self.pkg_commit_patch2)

    def test_commits_are_created(self):
        commits = PackageCommitPatch.objects.all()
        assert commits.count() == 2

    def test_commit_fields(self):
        commit = PackageCommitPatch.objects.get(
            commit_hash="8c001a11dbcb3eb6d851e18f4cefa080af5fb398"
        )
        assert commit.vcs_url == "https://github.com/aboutcode-org/test1/"
        assert commit.patch_text == "test1"

    def test_impacted_packages_creation(self):
        assert ImpactedPackage.objects.count() == 1
        assert self.pkg_commit_patch1 == self.impacted.fixed_by_package_commit_patches.first()
        assert self.pkg_commit_patch2 == self.impacted.introduced_by_package_commit_patches.first()

    def test_invalid_commit_creation(self):
        with pytest.raises(ValidationError):
            commit = PackageCommitPatch(
                commit_hash="", vcs_url="https://github.com/aboutcode-org/test1/"  # invalid
            )
            commit.full_clean()  # triggers model validation
            commit.save()

        with pytest.raises(ValidationError):
            commit = PackageCommitPatch(
                commit_hash="7c001a11dbcb3eb6d851e18f4cefa080af5fb398", vcs_url=""  # invalid
            )
            commit.full_clean()  # triggers model validation
            commit.save()
