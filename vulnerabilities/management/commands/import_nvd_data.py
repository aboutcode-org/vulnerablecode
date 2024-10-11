import os
import json
from django.core.management.base import BaseCommand
from django.db import IntegrityError
from vulnerabilities.models import Vulnerability, VulnerabilityReference, Package, PackageRelatedVulnerability
from vulnerablecode.settings import PROJECT_DIR

class Command(BaseCommand):
    help = 'Imports JSON vulnerability data into the database'

    def handle(self, *args, **kwargs):
        self.processed_files_count = 0
        self.skipped_files_count = 0
        self.error_files_count = 0
        
        data_directory = PROJECT_DIR / 'data'  
        self.process_files_in_directory(data_directory)
        
        self.stdout.write(self.style.SUCCESS(
            f"Data import completed. Processed: {self.processed_files_count}, Skipped: {self.skipped_files_count}, Errors: {self.error_files_count}"
        ))

    def process_files_in_directory(self, directory_path):
        for root_dir, sub_dirs, files in os.walk(directory_path):
            for file_name in files:
                if file_name.endswith('.json'):
                    file_path = os.path.join(root_dir, file_name)
                    self.process_single_json_file(file_path)

    def process_single_json_file(self, file_path):
        try:
            with open(file_path, 'r') as file:
                json_data = json.load(file)
                self.save_data_to_db(json_data)
                self.processed_files_count += 1
        except Exception as error:
            self.error_files_count += 1
            self.stdout.write(f"Error processing file {file_path}: {error}")

    def save_data_to_db(self, json_data):
        try:
            cve_id = json_data["_annotation"]["cve_id"]
            summary_reason = json_data["_annotation"].get("reason", "No specific reason provided")

            configurations = json_data.get("cve", {}).get("configurations", [])
            if configurations and configurations[0].get("nodes") and configurations[0]["nodes"][0].get("cpeMatch"):
                cpe_info = configurations[0]["nodes"][0]["cpeMatch"][0]
                criteria = cpe_info.get("criteria", "")
                version_limit = cpe_info.get("versionEndExcluding", "")
            else:
                self.skipped_files_count += 1
                self.stdout.write(f'Skipping file with incomplete "cpeMatch" data: {json_data}')
                return

            vulnerability, _ = Vulnerability.objects.get_or_create(
                vulnerability_id=cve_id,
                defaults={'summary': summary_reason}
            )

            reference_url = json_data["_annotation"].get("generated_from", "")
            VulnerabilityReference.objects.get_or_create(
                url=reference_url,
                reference_type="advisory"
            )

            cpe_parts = criteria.split(':')
            package_type = cpe_parts[2] if len(cpe_parts) > 2 else ''
            namespace = cpe_parts[3] if len(cpe_parts) > 3 else ''
            package_name = cpe_parts[4] if len(cpe_parts) > 4 else ''
            platform = cpe_parts[7] if len(cpe_parts) > 7 else ''

            version_limit = version_limit or ""

            full_package_url = criteria
            plain_package_url = self.build_plain_package_url(package_type, namespace, package_name, platform)

            package, created = Package.objects.get_or_create(
                type=package_type,
                namespace=namespace,
                name=package_name,
                version=version_limit,
                qualifiers='',
                subpath='',
                defaults={'package_url': full_package_url, 'plain_package_url': plain_package_url}
            )

            if created:
                try:
                    PackageRelatedVulnerability.objects.create(
                        package=package,
                        vulnerability=vulnerability,
                        fix=False,
                        confidence=100,
                        created_by='data_import_script'
                    )
                except IntegrityError:
                    self.stdout.write(f"IntegrityError: duplicate link for package {package.name} and vulnerability {vulnerability.vulnerability_id}")

        except KeyError as key_error:
            self.error_files_count += 1
            self.stdout.write(f"Missing key {key_error} in file: {json_data}")
        except IntegrityError as integrity_error:
            self.error_files_count += 1
            self.stdout.write(f"IntegrityError while processing data: {integrity_error}")
        except Exception as generic_error:
            self.error_files_count += 1
            self.stdout.write(f"Error processing file: {generic_error}")

    def build_plain_package_url(self, package_type, namespace, package_name, platform):
        return f"pkg:{package_type}/{namespace}/{package_name}@{platform}"
