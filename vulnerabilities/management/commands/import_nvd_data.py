import json
import requests
import time
from django.core.management.base import BaseCommand
from django.db import IntegrityError
from vulnerabilities.models import Vulnerability, VulnerabilityReference, Package, PackageRelatedVulnerability

class Command(BaseCommand):
    help = 'Import vulnerability data from GitHub JSON files into the database.'

    def handle(self, *args, **kwargs):
        self.total_files_processed = 0
        self.total_errors = 0

        start_time = time.time()  

        github_repo = "anchore/nvd-data-overrides"  # GitHub repository
        github_token = "your_github_token"  # Replace with your GitHub access token
        self.process_files_from_github(github_repo, github_token)

        end_time = time.time()  
        elapsed_time = end_time - start_time

        self.stdout.write(self.style.SUCCESS(
            f"Import completed: Processed {self.total_files_processed} files, Errors: {self.total_errors}, Time taken: {elapsed_time:.2f} seconds"
        ))

    def process_files_from_github(self, repo, token):
        latest_commit_url = f"https://api.github.com/repos/{repo}/commits/main"
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(latest_commit_url, headers=headers)

        if response.status_code == 200:
            commit_data = response.json()
            tree_sha = commit_data.get("commit", {}).get("tree", {}).get("sha")
            if tree_sha:
                self.fetch_git_tree(repo, tree_sha, headers)
            else:
                self.stdout.write("Could not find tree SHA in commit data.")
        else:
            self.stdout.write(f"Error fetching latest commit: {response.status_code} - {response.text}")

    def fetch_git_tree(self, repo, tree_sha, headers):
        git_tree_url = f"https://api.github.com/repos/{repo}/git/trees/{tree_sha}?recursive=1"
        response = requests.get(git_tree_url, headers=headers)

        if response.status_code == 200:
            tree_data = response.json()
            files = tree_data.get("tree", [])
            for file in files:
                if file['type'] == 'blob' and file['path'].endswith('.json'):
                    file_url = f"https://raw.githubusercontent.com/{repo}/main/{file['path']}"
                    self.process_file(file_url, headers)
        else:
            self.stdout.write(f"Error fetching git tree: {response.status_code} - {response.text}")

    def process_file(self, file_url, headers):
        try:
            response = requests.get(file_url, headers=headers)
            if response.status_code == 200:
                json_data = response.json()
                self.save_vulnerability(json_data)
                self.total_files_processed += 1
                self.stdout.write(f"Successfully processed file: {file_url}")
            else:
                self.total_errors += 1
                self.stdout.write(f"Error fetching file from GitHub: {response.status_code} - {response.text}")
        except Exception as error:
            self.total_errors += 1
            self.stdout.write(f"Error processing file: {error}")

    def save_vulnerability(self, json_data):
        try:
            cve_id = json_data.get("cve", {}).get("CVE_data_meta", {}).get("ID") or json_data.get("_annotation", {}).get("cve_id")
            if not cve_id:
                self.stdout.write("Skipping file: missing CVE ID.")
                return

            reason = json_data.get("_annotation", {}).get("reason", "No specific reason provided")
            vulnerability, _ = Vulnerability.objects.get_or_create(
                vulnerability_id=cve_id, defaults={'summary': reason}
            )

            reference_url = json_data.get("_annotation", {}).get("generated_from", "")
            if reference_url:
                VulnerabilityReference.objects.get_or_create(
                    url=reference_url, reference_type="advisory", defaults={'vulnerability': vulnerability}
                )

            configurations = json_data.get("cve", {}).get("configurations", [])
            for config in configurations:
                nodes = config.get("nodes", [])
                for node in nodes:
                    for match in node.get("cpeMatch", []):
                        self.handle_cpe_match(match, vulnerability)
        except KeyError as key_error:
            self.total_errors += 1
            self.stdout.write(f"Missing key {key_error} in file.")
        except IntegrityError as integrity_error:
            self.total_errors += 1
            self.stdout.write(f"Database error: {integrity_error}")
        except Exception as error:
            self.total_errors += 1
            self.stdout.write(f"Error saving vulnerability: {error}")

    def handle_cpe_match(self, cpe_match, vulnerability):
        criteria = cpe_match.get("criteria", "")
        if not criteria:
            return

        cpe_parts = criteria.split(':')
        package_type = cpe_parts[2] if len(cpe_parts) > 2 else ''
        namespace = cpe_parts[3] if len(cpe_parts) > 3 else ''
        package_name = cpe_parts[4] if len(cpe_parts) > 4 else ''
        platform = cpe_parts[7] if len(cpe_parts) > 7 else ''

        package, created = Package.objects.get_or_create(
            type=package_type,
            namespace=namespace,
            name=package_name,
            version=cpe_match.get("versionEndExcluding") or cpe_match.get("versionStartIncluding") or cpe_match.get("versionEndIncluding"),
            qualifiers='',
            subpath='',
            defaults={'package_url': criteria, 'plain_package_url': self.build_package_url(package_type, namespace, package_name, platform)}
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
                self.stdout.write(f"Duplicate link for package {package.name} and vulnerability {vulnerability.vulnerability_id}")

    def build_package_url(self, package_type, namespace, package_name, platform):
        return f"pkg:{package_type}/{namespace}/{package_name}@{platform}"