from datetime import datetime

import pytest

from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import CodeCommit
from vulnerabilities.models import ImpactedPackage


@pytest.mark.django_db
class TestCodeCommit:
    def setup_method(self):
        date = datetime.now()
        adv = AdvisoryV2.objects.create(
            unique_content_id="test_id",
            url="https://example.com",
            summary="summary",
            date_imported=date,
            date_collected=date,
            advisory_id="test_id",
            avid="test_pipeline/test_id",
            datasource_id="test_pipeline",
        )

        self.impacted = ImpactedPackage.objects.create(
            advisory=adv,
            base_purl="pkg:pypi/redis",
        )

        self.code_commit1 = CodeCommit.objects.create(
            commit_hash="8c001a11dbcb3eb6d851e18f4cefa080af5fb398",
            vcs_url="https://github.com/aboutcode-org/test1/",
            commit_author="tester1",
            commit_message="test message1",
            commit_date=datetime.now(),
        )

        self.code_commit2 = CodeCommit.objects.create(
            commit_hash="8c001a1",
            vcs_url="https://github.com/aboutcode-org/test1/",
        )

        self.impacted.fixed_by_commits.add(self.code_commit1)
        self.impacted.affecting_commits.add(self.code_commit2)

    def test_commits_are_created(self):
        commits = CodeCommit.objects.all()
        assert commits.count() == 2

    def test_commit_fields(self):
        commit = CodeCommit.objects.get(commit_hash="8c001a11dbcb3eb6d851e18f4cefa080af5fb398")
        assert commit.commit_author == "tester1"
        assert "test message1" == commit.commit_message
        assert commit.commit_date is not None

    def test_impacted_packages_creation(self):
        assert ImpactedPackage.objects.count() == 1
        assert self.code_commit1 == self.impacted.fixed_by_commits.first()
