from django.contrib import admin

from vulnerabilities.models import (
    ImpactedPackage,
    Package,
    PackageReference,
    ResolvedPackage,
    Vulnerability,
    VulnerabilityReference
)


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    pass


@admin.register(VulnerabilityReference)
class VulnerabilityReferenceAdmin(admin.ModelAdmin):
    pass


@admin.register(Package)
class PackageAdmin(admin.ModelAdmin):
    pass


@admin.register(ImpactedPackage)
class ImpactedPackageAdmin(admin.ModelAdmin):
    pass


@admin.register(ResolvedPackage)
class ResolvedPackageAdmin(admin.ModelAdmin):
    pass


@admin.register(PackageReference)
class PackageReferenceAdmin(admin.ModelAdmin):
    pass
