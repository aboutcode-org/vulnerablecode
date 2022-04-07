from vulnerabilities import importers
from vulnerabilities.improvers import default

IMPROVERS_REGISTRY = [
    importers.example.ExampleAliasImprover,
    default.DefaultImprover,
    importers.nginx.NginxBasicImprover,
    importers.alpine_linux.AlpineBasicImprover,
    importers.github.GitHubBasicImprover,
    importers.nvd.NVDBasicImprover,
]

IMPROVERS_REGISTRY = {x.qualified_name: x for x in IMPROVERS_REGISTRY}
