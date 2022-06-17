#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import hashlib
import json
import logging
import uuid

from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator
from django.core.validators import MinValueValidator
from django.db import models
from django.utils.http import int_to_base36
from packageurl import PackageURL
from packageurl.contrib.django.models import PackageURLMixin

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.improver import MAX_CONFIDENCE
from vulnerabilities.severity_systems import SCORING_SYSTEMS

logger = logging.getLogger(__name__)


class Vulnerability(models.Model):
    """
    A software vulnerability with minimal information. Unique identifiers are
    stored as ``Alias``.
    """

    vulnerability_id = models.CharField(
        unique=True,
        blank=True,
        max_length=20,
        help_text="Unique identifier for a vulnerability in the external representation. "
        "It is prefixed with VULCOID-",
    )

    summary = models.TextField(
        help_text="Summary of the vulnerability",
        blank=True,
    )

    references = models.ManyToManyField(
        to="VulnerabilityReference", through="VulnerabilityRelatedReference"
    )
    packages = models.ManyToManyField(
        to="Package",
        through="PackageRelatedVulnerability",
    )

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        if not self.vulnerability_id:
            self.vulnerability_id = f"VULCOID-{int_to_base36(self.id).upper()}"
            super().save(update_fields=["vulnerability_id"])

    @property
    def vulnerable_to(self):
        """
        Return packages that are vulnerable to this vulnerability.
        """
        return self.packages.filter(packagerelatedvulnerability__fix=False)

    @property
    def resolved_to(self):
        """
        Returns packages that first received patch against this vulnerability
        in their particular version history.
        """
        return self.packages.filter(packagerelatedvulnerability__fix=True)

    @property
    def alias(self):
        """
        Returns packages that first received patch against this vulnerability
        in their particular version history.
        """
        return self.aliases.all()

    def __str__(self):
        return self.vulnerability_id

    class Meta:
        verbose_name_plural = "Vulnerabilities"


class VulnerabilityReference(models.Model):
    """
    A reference to a vulnerability such as a security advisory from a Linux distribution or language
    package manager.
    """

    vulnerabilities = models.ManyToManyField(
        to="Vulnerability",
        through="VulnerabilityRelatedReference",
    )

    url = models.URLField(
        max_length=1024, help_text="URL to the vulnerability reference", blank=True
    )
    reference_id = models.CharField(
        max_length=200,
        help_text="An optional reference ID, such as DSA-4465-1 when available",
        blank=True,
    )

    @property
    def severities(self):
        return VulnerabilitySeverity.objects.filter(reference=self.id)

    class Meta:
        unique_together = (
            "url",
            "reference_id",
        )

    def __str__(self):
        reference_id = f" {self.reference_id}" if self.reference_id else ""
        return f"{self.url}{reference_id}"


class VulnerabilityRelatedReference(models.Model):
    """
    A reference related to a vulnerability.
    """

    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.CASCADE,
    )

    reference = models.ForeignKey(
        VulnerabilityReference,
        on_delete=models.CASCADE,
    )

    class Meta:
        unique_together = ("vulnerability", "reference")


class Package(PackageURLMixin):
    """
    A software package with related vulnerabilities.
    """

    vulnerabilities = models.ManyToManyField(
        to="Vulnerability", through="PackageRelatedVulnerability"
    )

    # Remove the `qualifers` and `set_package_url` overrides after
    # https://github.com/package-url/packageurl-python/pull/35
    # https://github.com/package-url/packageurl-python/pull/67
    # gets merged
    qualifiers = models.JSONField(
        default=dict,
        help_text="Extra qualifying data for a package such as the name of an OS, "
        "architecture, distro, etc.",
        blank=True,
        null=False,
    )

    class Meta:
        unique_together = (
            "type",
            "namespace",
            "name",
            "version",
            "qualifiers",
            "subpath",
        )

    @property
    # TODO: consider renaming to "affected_by"
    def vulnerable_to(self):
        """
        Returns vulnerabilities which are affecting this package.
        """
        return self.vulnerabilities.filter(packagerelatedvulnerability__fix=False)

    @property
    # TODO: consider renaming to "fixes" or "fixing" ? (TBD) and updating the docstring
    def resolved_to(self):
        """
        Returns the vulnerabilities which this package is patched against.
        """
        return self.vulnerabilities.filter(packagerelatedvulnerability__fix=True)

    def set_package_url(self, package_url):
        """
        Set each field values to the values of the provided `package_url` string
        or PackageURL object. Existing values are overwritten including setting
        values to None for provided empty values.
        """
        if not isinstance(package_url, PackageURL):
            package_url = PackageURL.from_string(package_url)

        for field_name, value in package_url.to_dict().items():
            model_field = self._meta.get_field(field_name)

            if value and len(value) > model_field.max_length:
                raise ValidationError(f'Value too long for field "{field_name}".')

            setattr(self, field_name, value or None)

    def __str__(self):
        return self.package_url


class PackageRelatedVulnerability(models.Model):

    # TODO: Fix related_name
    package = models.ForeignKey(
        Package,
        on_delete=models.CASCADE,
    )
    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.CASCADE,
    )
    created_by = models.CharField(
        max_length=100,
        blank=True,
        help_text="Fully qualified name of the improver prefixed with the"
        "module name responsible for creating this relation. Eg:"
        "vulnerabilities.importers.nginx.NginxBasicImprover",
    )

    confidence = models.PositiveIntegerField(
        default=MAX_CONFIDENCE,
        validators=[MinValueValidator(0), MaxValueValidator(MAX_CONFIDENCE)],
        help_text="Confidence score for this relation",
    )

    fix = models.BooleanField(
        default=False, help_text="Does this relation fix the specified vulnerability ?"
    )

    def __str__(self):
        return f"{self.package.package_url} {self.vulnerability.vulnerability_id}"

    class Meta:
        unique_together = ("package", "vulnerability")
        verbose_name_plural = "PackageRelatedVulnerabilities"
        indexes = [models.Index(fields=["fix"])]

    def update_or_create(self):
        """
        Update if supplied record has more confidence than existing record
        Create if doesn't exist
        """
        try:
            existing = PackageRelatedVulnerability.objects.get(
                vulnerability=self.vulnerability, package=self.package
            )
            if self.confidence > existing.confidence:
                existing.created_by = self.created_by
                existing.confidence = self.confidence
                existing.fix = self.fix
                existing.save()
                # TODO: later we want these to be part of a log field in the DB
                logger.info(
                    f"Confidence improved for {self.package} R {self.vulnerability}, "
                    f"new confidence: {self.confidence}"
                )

        except self.DoesNotExist:
            PackageRelatedVulnerability.objects.create(
                vulnerability=self.vulnerability,
                created_by=self.created_by,
                package=self.package,
                confidence=self.confidence,
                fix=self.fix,
            )
            logger.info(
                f"New relationship {self.package} R {self.vulnerability}, "
                f"fix: {self.fix}, confidence: {self.confidence}"
            )


class VulnerabilitySeverity(models.Model):

    reference = models.ForeignKey(VulnerabilityReference, on_delete=models.CASCADE)

    scoring_system_choices = tuple(
        (system.identifier, system.name) for system in SCORING_SYSTEMS.values()
    )

    scoring_system = models.CharField(
        max_length=50,
        choices=scoring_system_choices,
        help_text="Identifier for the scoring system used. Available choices are: {} ".format(
            ", ".join(
                f"{sid} is vulnerability_id for {sname} system"
                for sid, sname in scoring_system_choices
            )
        ),
    )

    value = models.CharField(max_length=50, help_text="Example: 9.0, Important, High")

    class Meta:
        unique_together = (
            "reference",
            "scoring_system",
            "value",
        )


class Alias(models.Model):
    """
    An alias is a unique vulnerability identifier in some database, such as
    the NVD, PYSEC, CVE or similar. These databases guarantee that these
    identifiers are unique within their namespace.
    An alias may also be used as a Reference. But in contrast with some
    Reference may not be an identifier for a single vulnerability, for instance,
    security advisories such as Debian security advisory reference various
    vulnerabilities.
    """

    alias = models.CharField(
        max_length=50,
        unique=True,
        help_text="An alias is a unique vulnerability identifier in some database, "
        "such as CVE-2020-2233",
    )

    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.CASCADE,
        related_name="aliases",
    )

    def __str__(self):
        return self.alias


class Advisory(models.Model):
    """
    An advisory represents data directly obtained from upstream transformed
    into structured data
    """

    unique_content_id = models.CharField(
        max_length=32,
        blank=True,
    )
    aliases = models.JSONField(blank=True, default=list, help_text="A list of alias strings")
    summary = models.TextField(
        blank=True,
    )
    # we use a JSON field here to avoid creating a complete relational model for data that
    # is never queried directly; instead it is only retrieved and processed as a whole by
    # an improver
    affected_packages = models.JSONField(
        blank=True, default=list, help_text="A list of serializable AffectedPackage objects"
    )
    references = models.JSONField(
        blank=True, default=list, help_text="A list of serializable Reference objects"
    )
    date_published = models.DateTimeField(
        blank=True, null=True, help_text="UTC Date of publication of the advisory"
    )
    date_collected = models.DateTimeField(help_text="UTC Date on which the advisory was collected")
    date_improved = models.DateTimeField(
        blank=True,
        null=True,
        help_text="Latest date on which the advisory was improved by an improver",
    )
    created_by = models.CharField(
        max_length=100,
        help_text="Fully qualified name of the importer prefixed with the"
        "module name importing the advisory. Eg:"
        "vulnerabilities.importers.nginx.NginxImporter",
    )

    class Meta:
        unique_together = (
            "aliases",
            "unique_content_id",
            "date_published",
        )

    def save(self, *args, **kwargs):
        checksum = hashlib.md5()
        for field in (self.summary, self.affected_packages, self.references):
            value = json.dumps(field, separators=(",", ":")).encode("utf-8")
            checksum.update(value)
        self.unique_content_id = checksum.hexdigest()
        super().save(*args, **kwargs)

    def to_advisory_data(self) -> AdvisoryData:
        return AdvisoryData(
            aliases=self.aliases,
            summary=self.summary,
            affected_packages=[AffectedPackage.from_dict(pkg) for pkg in self.affected_packages],
            references=[Reference.from_dict(ref) for ref in self.references],
            date_published=self.date_published,
        )
