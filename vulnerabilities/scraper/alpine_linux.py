import itertools
import saneyaml
from urllib.request import urlopen
from io import BytesIO
from zipfile import ZipFile

ALPINE_DB_URL = 'https://gitlab.alpinelinux.org/alpine/infra/alpine-secdb/-/\
archive/master/alpine-secdb-master.zip'


def alpine_advisories(url):
    with urlopen(url) as response:
        with ZipFile(BytesIO(response.read())) as zf:
            for path in zf.namelist():
                if path.endswith('main.yaml'):
                    yield saneyaml.load(zf.open(path))


def import_vulnerabilities():
    vulnerability_package_dicts = []
    for vulnerability in alpine_advisories(ALPINE_DB_URL):
        for pkg_details in vulnerability['packages']:
            package_name = pkg_details['pkg']['name']
            for version, fixed_cves in pkg_details['pkg']['secfixes'].items():
                # ['CVE-2016-9932  XSA-200', 'CVE-2016-9815','CVE-????-?????'] after mapping
                # the split  function to above list
                all_cves = list(map(lambda x: x.split(), fixed_cves))
                # it becomes   [['CVE-2016-9932','XSA-200'], ['CVE-2016-9815'],['CVE-????-?????']]
                for index, vuln_grp in enumerate(all_cves):
                    all_cves[index] = list(
                        filter(lambda x: 'CVE-????-?????' not in x, vuln_grp))
                all_cves = [i for i in all_cves if i and len(i) <= 2]
                # this data consists lots of 'CVE-????-?????' to denote vulnerabilities
                # with unassigned  CVE ids , we filter out these as well as other garbage data
                vulnerability_package_dicts.append(
                    {
                        'package_name': package_name,
                        'vuln_ids': all_cves,
                        'fixed_version': version,
                    }
                )
    return vulnerability_package_dicts
