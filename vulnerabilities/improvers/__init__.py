from . import default

IMPROVER_REGISTRY = [default.DefaultImprover]

improver_mapping = {f"{x.__module__}.{x.__name__}": x for x in IMPROVER_REGISTRY}
