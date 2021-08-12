IMPROVER_REGISTRY = []

def class_name(module_name: str):
    for improver in IMPROVER_REGISTRY:
        if improver.__module__ == module_name:
            return improver

    raise AttributeError
