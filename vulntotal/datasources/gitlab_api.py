import requests
import saneyaml


def fetch_directory_contents(package_slug):
    url = f"https://gitlab.com/api/v4/projects/12006272/repository/tree?path={package_slug}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    return []


def fetch_yaml(file_path):
    response = requests.get(
        f"https://gitlab.com/gitlab-org/security-products/gemnasium-db/-/raw/master/{file_path}"
    )
    if response.status_code == 200:
        return response.text
    return None


def get_package_slug(purl, supported_ecosystem):
    if purl.type not in supported_ecosystem:
        return
    ecosystem = supported_ecosystem[purl.type]
    package_name = purl.name
    if purl.type in ("maven", "composer", "golang"):
        package_name = f"{purl.namespace}/{purl.name}"
    return f"{ecosystem}/{package_name}"


def get_directory_yml_files(purl, supported_ecosystem, get_casesensitive_slug):
    package_slug = get_package_slug(purl, supported_ecosystem)
    directory_files = fetch_directory_contents(package_slug)
    if not directory_files:
        path = supported_ecosystem[purl.type]
        casesensitive_package_slug = get_casesensitive_slug(path, package_slug)
        directory_files = fetch_directory_contents(casesensitive_package_slug)
    if not directory_files:
        return []
    return [file for file in directory_files if file["name"].endswith(".yml")]


def fetch_gitlab_advisories_for_purl(purl, supported_ecosystem, get_casesensitive_slug):
    yml_files = get_directory_yml_files(purl, supported_ecosystem, get_casesensitive_slug)

    advisories = []
    for file in yml_files:
        yml_data = fetch_yaml(file["path"])
        if yml_data:
            advisories.append(saneyaml.load(yml_data))
    return advisories


def get_estimated_advisories_count(purl, supported_ecosystem, get_casesensitive_slug):
    return len(get_directory_yml_files(purl, supported_ecosystem, get_casesensitive_slug))
