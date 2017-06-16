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
    if not name:
        return None

    if version:
        url = 'https://cve.circl.lu/api/search/{name}/{version}'
    else:
        url = 'https://cve.circl.lu/api/search/{name}'

    raw_data = urlopen(url).read()

    data = json.loads(raw_data)

    if data:
        for item in data['data']:
            return item['id']
    else:
        return None

if __name__ == '__main__':
    output_cve_id()
