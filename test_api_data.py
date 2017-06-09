import api_data as api

from mock import Mock
import pytest
from urllib import urlopen

test_data = '''
{	"data": [
        {
            "Modified": "2008-11-15T00:00:00",
            "Published": "2007-02-19T21:28:00",
            "access": {
                "authentication": "NONE",
                "complexity": "MEDIUM",
                "vector": "NETWORK"
            },
            "cvss": 4.3,
            "cvss-time": "2007-02-20T14:55:00",
            "id": CVE-2007-1004"
            "impact": {
                "availability": "NONE",
                "confidentiality": "NONE",
                "integrity": "PARTIAL"
            },
            "reason": "Link",
            "references": [
                "http://securityreason.com/securityalert/2264",
                "http://www.securityfocus.com/archive/1/archive/1/460369/100/0/threaded",
                "http://www.securityfocus.com/archive/1/archive/1/460412/100/0/threaded",
                "http://www.securityfocus.com/archive/1/archive/1/460617/100/0/threaded",
                "http://www.securityfocus.com/bid/22601",
                "http://xforce.iss.net/xforce/xfdb/32580"
            ],
            "summary": "Mozilla Firefox might allow remote attackers to conduct spoofing and phishing attacks by writing to an about:blank tab and overlaying the location bar.",
            "vulnerable_configuration": [
                "cpe:2.3:a:mozilla:firefox:2.0:rc3"
            ],
            "vulnerable_configuration_cpe_2_2": [
                "cpe:/a:mozilla:firefox:2.0:rc3"
            ]}]}
'''

def test_output_cve_id():
	
	##BUG##
	api.urlopen = Mock()
	api.urlopen.return_value = test_data
	api.output_cve_id()

	assert api.output_cve_id.data["data"]["item"] == "CVE-2007-1004"