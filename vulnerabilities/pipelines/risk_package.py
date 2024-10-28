from aboutcode.pipeline import LoopProgress

from vulnerabilities.models import Package
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.risk import calculate_pkg_risk


class ComputePackageRiskPipeline(VulnerableCodePipeline):
    """
    Risk Assessment Pipeline for Package Vulnerabilities: Iterate through the packages and evaluate their associated risk.
    """

    pipeline_id = "compute_package_risk"
    license_expression = None

    @classmethod
    def steps(cls):
        return (cls.add_risk_package,)

    def add_risk_package(self):
        affected_pkgs = Package.objects.filter(affected_by_vulnerabilities__isnull=False).distinct()

        self.log(f"Calculating risk for {affected_pkgs.count():,d} affected package records")

        progress = LoopProgress(total_iterations=affected_pkgs.count(), logger=self.log)

        updatables = []
        updated_package_count = 0
        batch_size = 1000

        for pkg in progress.iter(affected_pkgs):
            risk = calculate_pkg_risk(pkg)
            pkg.risk = risk
            updatables.append(pkg)

            if len(updatables) >= batch_size:
                try:
                    Package.objects.bulk_update(objs=updatables, fields=["risk"])
                    updated_package_count += len(updatables)
                except Exception as e:
                    self.log(f"Error updating packages: {e}")

                updatables.clear()

        if updatables:
            try:
                Package.objects.bulk_update(objs=updatables, fields=["risk"])
                updated_package_count += len(updatables)
            except Exception as e:
                self.log(f"Error updating remaining packages: {e}")

        self.log(f"Successfully added risk score for {updated_package_count:,d} package")
