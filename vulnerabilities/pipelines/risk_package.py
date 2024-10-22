from vulnerabilities.models import Package
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.risk import calculate_pkg_risk


class RiskPackagePipeline(VulnerableCodePipeline):
    """
    Risk Assessment Pipeline for Package Vulnerabilities: Iterate through the packages and evaluate their associated risk.
    """

    pipeline_id = "risk_package"
    license_expression = None

    @classmethod
    def steps(cls):
        return (cls.add_risk_package,)

    def add_risk_package(self):
        self.log(f"Add risk package pipeline ")

        updatables = []
        for pkg in Package.objects.filter(affected_by_vulnerabilities__isnull=False):
            risk = calculate_pkg_risk(pkg)
            pkg.risk = risk
            updatables.append(pkg)

        # Bulk update the 'risk' field for all packages
        Package.objects.bulk_update(objs=updatables, fields=["risk"], batch_size=1000)

        self.log(f"Successfully added risk package pipeline ")
