from vulnerabilities import importers
from vulnerabilities.improvers import default

IMPROVERS_REGISTRY = [default.DefaultImprover, importers.nginx.NginxBasicImprover]

IMPROVERS_REGISTRY = {x.qualified_name: x for x in IMPROVERS_REGISTRY}
