from . import default
from .. import importers

IMPROVER_REGISTRY = [default.DefaultImprover, importers.nginx.NginxBasicImprover]

improver_mapping = {f"{x.__module__}.{x.__name__}": x for x in IMPROVER_REGISTRY}
