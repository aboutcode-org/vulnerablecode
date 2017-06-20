# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.http import JsonResponse

from django.shortcuts import render

import vulncode_app.api_data as api

def package(request, name):
    """
    Queries the cve-search api with just
    a package name.
    """
    api.output_cve_id(name=name)

    return JsonResponse({'cve_id':api.ids,'summary':api.summary,'cvss':api.cvss})

def package_version(request, name, version):
    """
    Queries the cve-search api with a package
    name and version.
    """
    api.output_cve_id(name=name, version=version)

    return JsonResponse({'cve_id':api.ids,'summary':api.summary,'cvss':api.cvss})
