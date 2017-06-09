#!/usr/bin/env python

import json
from urllib import urlopen 

def output_cve_id(): 
	"""Takes as input, a package name, package version. 
	Queries cve-search' dataset for any reported 
	vulnerabilities of the requested package. If 
	vulnerability exists, outputs cve-id(s).
	"""
	package_name = raw_input('Enter package name: ')
	user_choice = raw_input('Do you have a package version? (Y/N): ')
	
	if user_choice == 'Y' or user_choice == 'y':
		package_ver = raw_input('Enter package version: ')
		url = 'https://cve.circl.lu/api/search/' + package_name + package_ver
	
	else:
		url = 'https://cve.circl.lu/api/search/' + package_name
	
	raw_data = urlopen(url).read()
	data = json.loads(raw_data)

	if len(data) > 0:
		print 'Vulnerabilties Found:\n'
		
		for item in data['data']:
			print item['id']
	else:
		print 'No vulnerabilites found'

if __name__ == '__main__':
	output_cve_id()