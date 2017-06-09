#!/usr/bin/env python

import json
import sys

"""Py version check"""
if sys.version_info[0] == 3:
    from urllib.request import urlopen
else: 
	from urllib import urlopen 

def output_cve_id(type=None, name=None, version=None): 
	"""Take as input, a package name, package version. 
	Queries cve-search' dataset for any reported 
	vulnerabilities of the requested package. If 
	vulnerability exists, outputs cve-id(s).
	"""
	if version:
		url = ('https://cve.circl.lu/api/search/{}/{}').format(name,version)
	else:
		url = ('https://cve.circl.lu/api/search/{}').format(name)
	
	raw_data = urlopen(url).read()
	data = json.loads(raw_data)

	if data:
		print ('Vulnerabilties Found:\n')
		
		for item in data['data']:
			print (item['id'])
	else:
		print ('No vulnerabilites found')

if __name__ == '__main__':
	output_cve_id()