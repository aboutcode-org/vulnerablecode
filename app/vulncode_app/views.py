# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.http import HttpResponse
from django.shortcuts import render

import vulncode_app.api_data as api

def product(request, product):
    """
    Queries the cve-search api with just
    a product name.
    """
    data = api.output_cve_id(name=product)
    return HttpResponse(data)

def product_ver(request, product, ver):
    """
    Queries the cve-search api with a product
    name and version.
    """
    data = api.output_cve_id(name=product, version=ver)
    return HttpResponse(data)
