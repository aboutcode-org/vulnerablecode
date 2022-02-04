from vulnerabilities.improvers import default
from vulnerabilities import importers

IMPROVERS_REGISTRY = [default.DefaultImprover, importers.nginx.NginxBasicImprover]

IMPROVERS_REGISTRY = {x.qualified_name: x for x in IMPROVERS_REGISTRY}
