#!/usr/bin/env python

import json
import sys
from urllib.request import urlopen

def output_cve_id(type=None, name=None, version=None):
    """Take as input, a package name, package version.
    Queries cve-search' dataset for any reported
    vulnerabilities of the requested package. If
    vulnerability exists, outputs cve-id(s).
    """
    id = []

    if not name:
        return 

    if version:
        url = f'https://cve.circl.lu/api/search/{name}/{version}'
    else:
        url = f'https://cve.circl.lu/api/search/{name}'

    raw_data = urlopen(url).read()
    data = json.loads(raw_data)

    if data and name and not version:
        for item in data['data']:
            id.append(item['id'])

        return id

    if data and version and name:
        for item in data:
            id.append(item['id'])          

        return id

if __name__ == '__main__':
    output_cve_id()
