
Package endpoint
------------------

We are moving from API v1 to API V3. 

- /api/packages earlier had "bulk_search", "bulk_lookup", "lookup" and "all" endpoints.

- /api/v3/packages has only one endpoint, which have same capabilities as all of these endpoints.

- Response by package endpoint, will always be paginated, with 10 results per page, and will have "next" and "previous" links for pagination. If there are more than 100 advisories for a package, then it will return "affected_by_vulnerabilities_url" and "fixing_vulnerabilities_url" instead of "affected_by_vulnerabilities" and "fixing_vulnerabilities" respectively.

"all"

- Instead of doing /api/packages/all, we can do /api/v3/packages with empty purls list.

- To get all vulnerable packages:

```
POST /api/v3/packages
{
    "purls": []
}
```

Response:

```

{
    "count": 596,
    "next": "http://example.com/api/v3/packages?page=2",
    "previous": null,
    "results": [
        "pkg:npm/626@1.1.1",
        "pkg:npm/aedes@0.35.0",
        "pkg:npm/airbrake@0.3.8",
        "pkg:npm/angular-http-server@1.4.3",
        "pkg:npm/apex-publish-static-files@2.0.0",
        "pkg:npm/atob@2.0.3",
        "pkg:npm/augustine@0.2.3",
        "pkg:npm/backbone@0.3.3",
        "pkg:npm/base64-url@1.3.3",
        "pkg:npm/base64url@2.0.0"
    ]
}
```


"bulk_search"

- Instead of doing /api/packages/bulk_search, we can do /api/v3/packages with purls list and "details" as false or true (by default it's false), earlier we had "purls_only" . Also, previosuly we used to have "plain_purl" as a parameter, to ignore qualifiers and subpaths in purls, now we have "approximate", if set to True will ignore qualifiers and subpaths in purls.

Examples:

- To get only purls of vulnerable packages:
```
POST /api/v3/packages
{
    "purls": ["pkg:npm/atob@2.0.3", "pkg:pypi/sample@2.0.0"],
    "details": false
}
```

Response:

```
{
    "count": 1,
    "next": null,
    "previous": null,
    "results": [
        "pkg:npm/atob@2.0.3"
    ]
}

```

- To get details of vulnerable packages:
```
POST /api/v3/packages
{
    "purls": ["pkg:npm/atob@2.0.3", "pkg:pypi/sample@2.0.0"],
    "details": true
}
```

Response:
```

{
    "count": 1,
    "next": null,
    "previous": null,
    "results": [
        {
            "purl": "pkg:npm/atob@2.0.3",
            "affected_by_vulnerabilities": [
                {
                    "advisory_id": "nodejs_security_wg/npm-403",
                    "fixed_by_packages": [
                        "pkg:npm/atob@2.1.0"
                    ],
                    "duplicate_advisory_ids": []
                }
            ],
            "fixing_vulnerabilities": [],
            "next_non_vulnerable_version": "2.1.0",
            "latest_non_vulnerable_version": "2.1.0",
            "risk_score": null
        }
    ]
}
```

- To get details of vulnerable packages by ignoring qualifiers and subpaths in purls:
```
POST /api/v3/packages
{
    "purls": ["pkg:npm/atob@2.0.3?foo=bar", "pkg:pypi/sample@2.0.0"],
    "approximate": true,
    "details": true
}
```

Response:
```

{
    "count": 1,
    "next": null,
    "previous": null,
    "results": [
        {
            "purl": "pkg:npm/atob@2.0.3",
            "affected_by_vulnerabilities": [
                {
                    "advisory_id": "nodejs_security_wg/npm-403",
                    "fixed_by_packages": [
                        "pkg:npm/atob@2.1.0"
                    ],
                    "duplicate_advisory_ids": []
                }
            ],
            "fixing_vulnerabilities": [],
            "next_non_vulnerable_version": "2.1.0",
            "latest_non_vulnerable_version": "2.1.0",
            "risk_score": null
        }
    ]
}
```

- To get vulnerable packages by ignoring qualifiers and subpaths in purls:
```
POST /api/v3/packages
{
    "purls": ["pkg:npm/atob@2.0.3?foo=bar"],
    "approximate": true,
}
```

Response:

```
{
    "count": 1,
    "next": null,
    "previous": null,
    "results": [
        "pkg:npm/atob@2.0.3"
    ]
}

```

Advisory endpoint
------------------

- You can get all advisories for a purl or list of purls by using /api/v3/advisories endpoint. It will also be paginated with 10 results per page, and will have "next" and "previous" links for pagination

```
POST /api/v3/advisories
{
    "purls": ["pkg:npm/atob@2.0.3", "pkg:pypi/sample@2.0.0"]
}
```

Response:

```
{
    "count": 1,
    "next": null,
    "previous": null,
    "results": [
        {
            "advisory_id": "nodejs_security_wg/npm-403",
            "url": "https://github.com/nodejs/security-wg/blob/main/vuln/npm/403.json",
            "aliases": [
                "CVE-2018-3745"
            ],
            "summary": "Out-of-bounds Read\n`atob` allocates uninitialized Buffers when number is passed in input on Node.js 4.x and below",
            "severities": [
                {
                    "url": "https://github.com/nodejs/security-wg/blob/main/vuln/npm/403.json",
                    "value": "6.5",
                    "scoring_system": "cvssv3",
                    "scoring_elements": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:H"
                }
            ],
            "weaknesses": [],
            "references": [
                {
                    "url": "https://hackerone.com/reports/321686",
                    "reference_type": "",
                    "reference_id": ""
                },
                {
                    "url": "https://github.com/nodejs/security-wg/blob/main/vuln/npm/403.json",
                    "reference_type": "",
                    "reference_id": "403"
                }
            ],
            "exploitability": null,
            "weighted_severity": null,
            "risk_score": null,
            "related_ssvc_trees": []
        }
    ]
}
```

Affected By Advisories endpoint
--------------------------------------

- You can get all advisories that fix a purl by using /api/v3/affected-by-advisories?purl=<purl> endpoint

```
GET /api/v3/affected-by-advisories?purl=pkg:npm/atob@2.0.3
```

Response:
```
{
    "count": 1,
    "next": null,
    "previous": null,
    "results": [
        {
            "advisory_id": "nodejs_security_wg/npm-403",
            "url": "https://github.com/nodejs/security-wg/blob/main/vuln/npm/403.json",
            "aliases": [
                "CVE-2018-3745"
            ],
            "summary": "Out-of-bounds Read\n`atob` allocates uninitialized Buffers when number is passed in input on Node.js 4.x and below",
            "severities": [
                {
                    "url": "https://github.com/nodejs/security-wg/blob/main/vuln/npm/403.json",
                    "value": "6.5",
                    "scoring_system": "cvssv3",
                    "scoring_elements": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:H"
                }
            ],
            "weaknesses": [],
            "references": [
                {
                    "url": "https://hackerone.com/reports/321686",
                    "reference_type": "",
                    "reference_id": ""
                },
                {
                    "url": "https://github.com/nodejs/security-wg/blob/main/vuln/npm/403.json",
                    "reference_type": "",
                    "reference_id": "403"
                }
            ],
            "exploitability": null,
            "weighted_severity": null,
            "risk_score": null,
            "related_ssvc_trees": []
        }
    ]
}
```

Fixing Advisories endpoint
-----------------------------

- You can get all advisories that are fixed by a purl by using /api/v3/fixing-advisories?purl=<purl> endpoint

```
GET /api/v3/fixing-advisories?purl=pkg:npm/atob@2.1.0
```

Response:
```
{
    "count": 1,
    "next": null,
    "previous": null,
    "results": [
        {
            "advisory_id": "nodejs_security_wg/npm-403",
            "url": "https://github.com/nodejs/security-wg/blob/main/vuln/npm/403.json",
            "aliases": [
                "CVE-2018-3745"
            ],
            "summary": "Out-of-bounds Read\n`atob` allocates uninitialized Buffers when number is passed in input on Node.js 4.x and below",
            "severities": [
                {
                    "url": "https://github.com/nodejs/security-wg/blob/main/vuln/npm/403.json",
                    "value": "6.5",
                    "scoring_system": "cvssv3",
                    "scoring_elements": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:H"
                }
            ],
            "weaknesses": [],
            "references": [
                {
                    "url": "https://hackerone.com/reports/321686",
                    "reference_type": "",
                    "reference_id": ""
                },
                {
                    "url": "https://github.com/nodejs/security-wg/blob/main/vuln/npm/403.json",
                    "reference_type": "",
                    "reference_id": "403"
                }
            ],
            "exploitability": null,
            "weighted_severity": null,
            "risk_score": null,
            "related_ssvc_trees": []
        }
    ]
}
```
