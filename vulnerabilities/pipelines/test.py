"""
whole in div gdoc-page
each advisory in article gdoc-markdown gdoc-post

"""

from bs4 import BeautifulSoup
import requests

root_url = "https://www.sudo.ws/security/advisories/"


def fetch_advisory_links(active_pages):
    advisory_links =[]
    for active_page in active_pages:
        html_content = requests.get(active_page).content

        # Parse the HTML content using BeautifulSoup
        soup = BeautifulSoup(html_content, "html.parser")

        # Find the <a> tag with the class "gdoc-post__readmore"
        readmore_links = soup.find_all("a", class_="gdoc-post__readmore")

        # Extract the href value
        
        for readmore_link in readmore_links:
            advisory_links.append("https://www.sudo.ws"+readmore_link["href"]) 
    return advisory_links       


def fetch_active_pages():
    page_num = 2
    active_pages = ["https://www.sudo.ws/security/advisories/"]
    while True:
        page_url = f"https://www.sudo.ws/security/advisories/page/{page_num}/"
        status = requests.get(page_url).status_code
        if status==404:
            break
        else:
            active_pages.append(page_url)
            page_num+=1

    return active_pages

"""active_pages = fetch_active_pages()
advisory_links = fetch_advisory_links(active_pages)
print(advisory_links)"""

def fetch_advisory_data(advisory_link):
    html_content = requests.get(advisory_link).content
    # Parse the HTML content using BeautifulSoup
    soup = BeautifulSoup(html_content, "html.parser")

    # Extract the publication date (datetime), set to None if it doesn't exist
    publication_date = soup.find("time").get("datetime", None) if soup.find("time") else None

    # Extract the first <p> element inside <section> (summary of the issue), set to None if it doesn't exist
    summary = soup.find("section", class_="gdoc-markdown").find("p").get_text(strip=True) if soup.find("section", class_="gdoc-markdown") else None

    # Extract "Sudo versions affected", set to None if it doesn't exist
    versions_affected_tag = soup.find("h2", id="sudo-versions-affected")
    versions_affected = versions_affected_tag.find_next("p").get_text(strip=True) if versions_affected_tag else None
    print("Sudo Versions Affected:", versions_affected)

    # Extract "CVE ID", set to None if it doesn't exist
    cve_id_tag = soup.find("h2", id="cve-id")
    cve_id = cve_id_tag.find_next("a", class_="gdoc-markdown__link").get_text(strip=True) if cve_id_tag else None

    # Extract "Fixed versions", set to None if it doesn't exist
    fixed_versions_tag = soup.find("h2", id="fix")
    fixed_versions = fixed_versions_tag.find_next("p").get_text(strip=True) if fixed_versions_tag else None
    print("Fixed Versions:", fixed_versions)

    return {
        "description": summary,
        "alias": cve_id,
        "date_published": publication_date,
        "affected_versions": versions_affected,
        "fixed_versions" : fixed_versions
    }

data = fetch_advisory_data("https://www.sudo.ws/security/advisories/sudoedit_escalate/")
print(data)