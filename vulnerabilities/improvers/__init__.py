from vulnerabilities.improvers import default
from vulnerabilities import importers

IMPROVERS = [default.DefaultImprover, importers.nginx.NginxBasicImprover]

IMPROVER_REGISTRY = {x.qualified_name: x for x in IMPROVERS}
