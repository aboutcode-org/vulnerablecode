from . import nginx

IMPROVER_REGISTRY = [nginx.NginxTimeTravel]

def find_class(class_name: str):
    # FIXME: this might cause problems when there are two modules containing same class name, think of a better approach
    for improver in IMPROVER_REGISTRY:
        if class_name == improver.__name__:
            return improver

    raise AttributeError
