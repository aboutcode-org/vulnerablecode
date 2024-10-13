from django.core.management.base import BaseCommand
from vulnerabilities.models import Package
from packaging.version import parse, InvalidVersion
from packageurl import PackageURL
import re

class VersionHandler:
    def __init__(self, version_string):
        self.original_version = str(version_string) if version_string is not None else ''
        self.parsed_version = self.parse_version(self.original_version)

    def parse_version(self, version_string):
        if not version_string:
            return (float('inf'),)
        
        # Handle date-based versions like YYYY-MM-DD
        date_match = re.match(r'(\d{4})-(\d{2})-(\d{2})', version_string)
        if date_match:
            return (int(date_match.group(1)), int(date_match.group(2)), int(date_match.group(3)), '', '')
        
        # Handle versions with underscores, e.g., 1.2.3_4
        underscore_match = re.match(r'(\d+)\.(\d+)\.(\d+)_(\d+)', version_string)
        if underscore_match:
            return (int(underscore_match.group(1)), int(underscore_match.group(2)), 
                    int(underscore_match.group(3)), int(underscore_match.group(4)), '')
        
        # Handle versions with build metadata, e.g., 1.2.3-alpha
        build_match = re.match(r'(\d+)\.(\d+)\.(\d+)([.-].+)', version_string)
        if build_match:
            return (int(build_match.group(1)), int(build_match.group(2)), 
                    int(build_match.group(3)), build_match.group(4), '')
        
        # Handle git commit hashes (40-character hex strings)
        if re.match(r'^[a-f0-9]{40}$', version_string):
            return (0, 0, 0, '', version_string)
        
        # Attempt to parse using standard version parsing
        try:
            parsed = parse(version_string)
            return (parsed.major, parsed.minor, parsed.micro, parsed.pre, parsed.post)
        except InvalidVersion:
            return (float('inf'),)

    def __lt__(self, other):
        if not isinstance(other, VersionHandler):
            return NotImplemented
        return self.parsed_version < other.parsed_version

    def __eq__(self, other):
        if not isinstance(other, VersionHandler):
            return NotImplemented
        return self.parsed_version == other.parsed_version

def extract_ecosystem_from_purl(purl):
    try:
        return PackageURL.from_string(purl).type if purl else ''
    except ValueError:
        return ''

def check_if_prerelease(version):
    return bool(version.parsed_version and len(version.parsed_version) > 3 and version.parsed_version[3])

class Command(BaseCommand):
    help = 'Update version ordering and pre-release fields for existing packages'

    def add_arguments(self, parser):
        parser.add_argument('--batch-size', type=int, default=1000, help='Number of packages to process in each batch')

    def handle(self, *args, **options):
        batch_size = options['batch_size']
        packages = Package.objects.all()
        total_packages = packages.count()
        updated_packages = 0
        invalid_version_packages = []
        packages_missing_version = []

        self.stdout.write(f"Processing {total_packages} packages in batches of {batch_size}")

        for start_index in range(0, total_packages, batch_size):
            package_batch = packages[start_index:start_index + batch_size]
            
            try:
                sorted_batch = sorted(
                    package_batch, 
                    key=lambda pkg: (
                        extract_ecosystem_from_purl(pkg.package_url), 
                        VersionHandler(pkg.version) if pkg.version else VersionHandler('')
                    )
                )
            except TypeError as error:
                self.stdout.write(self.style.ERROR(f"Type error during sorting: {str(error)}"))
                continue
            except Exception as error:
                self.stdout.write(self.style.ERROR(f"Unexpected error during sorting: {str(error)}"))
                continue

            for index, package in enumerate(sorted_batch):
                version_handler = VersionHandler(package.version)
                
                new_version_order = float(index + 1)
                is_prerelease = check_if_prerelease(version_handler)

                if package.version_order != new_version_order or package.is_pre_release != is_prerelease:
                    package.version_order = new_version_order
                    package.is_pre_release = is_prerelease
                    package.save()
                    updated_packages += 1

                if version_handler.parsed_version == (float('inf'),):
                    invalid_version_packages.append(package)
                if not package.version:
                    packages_missing_version.append(package)

            self.stdout.write(f"Processed {min(start_index + batch_size, total_packages)} / {total_packages} packages")

        self.stdout.write(self.style.SUCCESS(f'Updated {updated_packages} packages successfully.'))
        
        if invalid_version_packages:
            self.stdout.write(self.style.WARNING(f'Found {len(invalid_version_packages)} packages with invalid versions:'))
            for pkg in invalid_version_packages[:10]:
                self.stdout.write(f'  - Package ID: {pkg.id}, Version: {pkg.version}, PURL: {pkg.package_url}')
            if len(invalid_version_packages) > 10:
                self.stdout.write(f'  ... and {len(invalid_version_packages) - 10} more.')

        if packages_missing_version:
            self.stdout.write(self.style.WARNING(f'Found {len(packages_missing_version)} packages without versions:'))
            for pkg in packages_missing_version[:10]:
                self.stdout.write(f'  - Package ID: {pkg.id}, PURL: {pkg.package_url}')
            if len(packages_missing_version) > 10:
                self.stdout.write(f'  ... and {len(packages_missing_version) - 10} more.')