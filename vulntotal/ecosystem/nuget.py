#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from urllib.parse import urljoin

import requests

"""
Find case-sensitive NuGet package names using API calls.
Some data source such as OSV demand case-sensitive names.
"""


def get_closest_nuget_package_name(query):
    """
    Return case-sensitive NuGet package name using
    SearchQueryService provided by NuGet
    """
    url_nuget_service = "https://api.nuget.org/v3/index.json"
    url_nuget_search = ""

    api_resources = requests.get(url_nuget_service).json()
    for resource in api_resources.get("resources") or []:
        if resource.get("@type") == "SearchQueryService":
            url_nuget_search = resource["@id"]
            break

    if url_nuget_search:
        url_query = urljoin(url_nuget_search, f"?q={query}")
        query_response = requests.get(url_query).json()
        if query_response.get("data"):
            return query_response["data"][0]["id"]


def search_closest_nuget_package_name(query):
    """
    Return case-sensitive NuGet package name using
    the autocomplete service provided by NuGet
    The data has this shape:
        {
          "@context": {
            "@vocab": "http://schema.nuget.org/schema#"
          },
          "totalHits": 3145,
          "data": [
            "Azure.Core",
            "Azure.Storage.Blobs",
            "Azure.Security.KeyVault.Secrets",
            ...
    """
    url_query = f"https://azuresearch-usnc.nuget.org/autocomplete?q={query}"
    query_response = requests.get(url_query).json()
    data = query_response.get("data")
    if data:
        return data[0]
