from __future__ import unicode_literals
from django.http import HttpResponse
import json
from django.shortcuts import render
import vulncode_app.api_data as api

def package(request, name):
    """
    Queries the cve-search api with just
    a package name.
    """
    raw_data = api.data_cve_circl(name=name)
    fields_names = ['id', 'summary', 'cvss']
    extracted_data = api.extract_fields(raw_data, fields_names)

    return HttpResponse(json.dumps(extracted_data))

def package_version(request, name, version):
    """
    Queries the cve-search api with a package
    name and version.
    """
    raw_data = api.data_cve_circl(name=name, version=version)
    fields_names = ['id', 'summary', 'cvss']
    extracted_data = api.extract_fields(raw_data, fields_names, version=True)

    return HttpResponse(json.dumps(extracted_data))
