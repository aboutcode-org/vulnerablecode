from packageurl import PackageURL

from vulnerabilities.data_inference import Improver
from vulnerabilities.data_inference import Advisory
from vulnerabilities.data_inference import Inference
from vulnerabilities.helpers import nearest_patched_package
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import Package

class NginxTimeTravel(Improver):
    def updated_inferences(self):
        inferences = []

        vulnerabilities = set(Vulnerability.objects.filter(vulnerable_packages__name="nginx"))
        vulnerabilities.union(Vulnerability.objects.filter(patched_packages__name="nginx"))

        for vulnerability in vulnerabilities:
            affected_packages = map(package_url, Package.objects.filter(vulnerable_package__package__name="nginx", vulnerabilities = vulnerability))
            fixed_packages = map(package_url, Package.objects.filter(patched_package__package__name="nginx", vulnerabilities = vulnerability))

            time_traveller = nearest_patched_package(affected_packages, fixed_packages)
            affected_packages = [ affected_package.vulnerable_package for affected_package in time_traveller]
            fixed_packages = [ affected_package.patched_package for affected_package in time_traveller if affected_package.patched_package is not None]

            inference = Inference(advisory = Advisory(
                vulnerability_id=vulnerability.vulnerability_id,
                summary=vulnerability.summary,
                affected_package_urls=fixed_packages,
            ), source="time travel", confidence=30)
            inferences.append(inference)

        return inferences


def package_url(package):
    return PackageURL(
            type=package.type,
            namespace=package.namespace,
            name=package.name,
            version=package.version,
            subpath=package.subpath,
            qualifiers=package.qualifiers
            )

