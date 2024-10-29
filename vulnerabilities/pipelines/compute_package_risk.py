from aboutcode.pipeline import LoopProgress

from vulnerabilities.models import Package
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.risk import compute_package_risk


class ComputePackageRiskPipeline(VulnerableCodePipeline):
    """
    Risk Assessment Pipeline for Package Vulnerabilities: Iterate through the packages and evaluate their associated risk.
    """

    pipeline_id = "compute_package_risk"
    license_expression = None

    @classmethod
    def steps(cls):
        return (cls.add_package_risk_score,)

    def add_package_risk_score(self):
        affected_packages = Package.objects.filter(
            affected_by_vulnerabilities__isnull=False
        ).distinct()

        self.log(f"Calculating risk for {affected_packages.count():,d} affected package records")

        progress = LoopProgress(total_iterations=affected_packages.count(), logger=self.log)

        updatables = []
        updated_package_count = 0
        batch_size = 5000

        for package in progress.iter(affected_packages.paginated()):
            risk_score = compute_package_risk(package)
            package.risk_score = risk_score
            updatables.append(package)

            if len(updatables) >= batch_size:
                updated_package_count += bulk_update_package_risk_score(
                    packages=updatables,
                    logger=self.log,
                )
        updated_package_count += bulk_update_package_risk_score(
            packages=updatables,
            logger=self.log,
        )
        self.log(f"Successfully added risk score for {updated_package_count:,d} package")


def bulk_update_package_risk_score(packages, logger):
    package_count = 0
    if packages:
        try:
            Package.objects.bulk_update(objs=packages, fields=["risk_score"])
            package_count += len(packages)
        except Exception as e:
            logger(f"Error updating packages: {e}")
        packages.clear()
    return package_count
