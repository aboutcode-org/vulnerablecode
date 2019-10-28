# Author: Navonil Das (@NavonilDas)
import semantic_version
import re
import json
from urllib.request import urlopen

NPM_URL = 'https://registry.npmjs.org{}'
PAGE = '/-/npm/v1/security/advisories?page=1'
    
# Removes spaces and v Charecter in front of version 
def remove_spaces(x):
    x = re.sub(r" +"," ",x)     # Replace Multiple spaces to one
    # Remove space after the Relational operator
    x = re.sub(r'< +','<',x)
    x = re.sub(r'> +','>',x)
    x = re.sub(r'<= +','<=',x)
    x = re.sub(r'>= +','>=',x)
    # Remove v at starting of version
    x = re.sub(r'>=[vV]','>=',x)
    x = re.sub(r'<=[vV]','<=',x)
    x = re.sub(r'>[vV]','>',x)
    x = re.sub(r'<[vV]','<',x)
    return x


# Returns all available for a module
def get_all_version(package_name):
    package_url = NPM_URL.format('/'+package_name)
    response = urlopen(package_url).read()
    data = json.loads(response)
    versions = data.get('versions',{})
    all_version = [obj for obj in versions]
    return all_version

# Seperate list of Affected version and fixed version from all version
# using the range specified
def extract_version(package_name,aff_version_range,fixed_version_range):
    if aff_version_range == '' or fixed_version_range == '':
        return ([],[])
    
    aff_spec = semantic_version.NpmSpec(remove_spaces(aff_version_range))
    fix_spec = semantic_version.NpmSpec(remove_spaces(fixed_version_range))
    all_ver = get_all_version(package_name)
    aff_ver = []
    fix_ver = []
    for ver in all_ver:
        cur_version = semantic_version.Version(ver)
        if cur_version in aff_spec:
            aff_ver.append(ver)
        else:
            if cur_version in fix_spec:
                fix_ver.append(ver)
    
    return (aff_ver,fix_ver)


# Extract module name, summary, vulnerability id,severity
def extract_data(JSON):
    package_vulnerabilities = []
    for obj in JSON.get('objects',[]):
        if 'module_name' not in obj:
            continue
        package_name = obj['module_name']
        summary = obj.get('overview','')
        severity = obj.get('severity','')
        
        vulnerability_id = obj.get('cves',[])
        if len(vulnerability_id) > 0:
            vulnerability_id = vulnerability_id[0]
        else:
            vulnerability_id = ''

        affected_version,fixed_version = extract_version(
            package_name,
            obj.get('vulnerable_versions',''),
            obj.get('patched_versions','')
        )

        package_vulnerabilities.append({
            'package_name': package_name,
            'summary': summary,
            'vulnerability_id':vulnerability_id,
            'fixed_version':fixed_version,
            'affected_version':affected_version,
            'severity':severity
        })
    return package_vulnerabilities


# Extract JSON From NPM registry
def scrape_vulnerabilities():
    cururl = NPM_URL.format(PAGE)
    response = urlopen(cururl).read()
    package_vulnerabilities = []
    while True:
        data = json.loads(response)
        package_vulnerabilities = package_vulnerabilities + extract_data(data)
        next_page = data.get('urls',{}).get('next',False)
        if next_page:
            cururl = NPM_URL.format(next_page)
            response = urlopen(cururl).read()
        else:
            break
    return package_vulnerabilities

