#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from dataclasses import dataclass
from typing import Any
from typing import Callable
from typing import Dict
from typing import Optional

from django.contrib.postgres.fields import ArrayField
from django.db import models


class DailySnapshot(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        get_latest_by = "created_at"
        ordering = ["-created_at"]


class PackageInsight(models.Model):
    snapshot = models.ForeignKey(
        DailySnapshot, related_name="package_insights", on_delete=models.CASCADE
    )
    package = models.CharField(max_length=50)
    total_packages = models.IntegerField(default=0)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["snapshot", "package"], name="unique_snapshot_package")
        ]


class PackageNameInsight(models.Model):
    package_insight = models.ForeignKey(
        PackageInsight, related_name="names", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    count = models.IntegerField()

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["package_insight", "name"], name="unique_package_name")
        ]


class PackageCWEInsight(models.Model):
    package_insight = models.ForeignKey(
        PackageInsight, related_name="cwes", on_delete=models.CASCADE
    )
    cwe_id = models.CharField(max_length=50)
    count = models.IntegerField()

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["package_insight", "cwe_id"], name="unique_package_cwe")
        ]


class SeverityInsight(models.Model):
    snapshot = models.OneToOneField(
        DailySnapshot, related_name="severity_insight", on_delete=models.CASCADE
    )
    buckets = ArrayField(
        models.IntegerField(),
        size=10,
        default=list,
        help_text="Scores mapped to buckets 0-10 (e.g. 0.0-0.9 -> index 0)",
    )


class ImporterInsight(models.Model):
    snapshot = models.ForeignKey(
        DailySnapshot, related_name="importer_insights", on_delete=models.CASCADE
    )
    importer = models.CharField(max_length=100)
    total_advisories = models.IntegerField(default=0)
    advisories_with_packages = models.IntegerField(default=0)
    advisories_with_ghost_packages = models.IntegerField(default=0)
    advisories_with_kev = models.IntegerField(default=0)
    advisories_with_metasploit = models.IntegerField(default=0)
    advisories_with_exploitdb = models.IntegerField(default=0)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["snapshot", "importer"], name="unique_snapshot_importer"
            )
        ]


@dataclass(frozen=True)
class ChartDefinition:

    id: str
    title: str
    panel: str
    chart_type: str
    formatter_fn: Callable[[Dict[str, Any]], Dict[str, Any]]
    collect_fn: Optional[Callable] = None
    is_per_package: bool = False
    has_search: bool = False
