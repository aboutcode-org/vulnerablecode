def filter_purls(purls, allowed_types=None):
    if not purls:
        return []
    if not allowed_types:
        return [p for p in purls if p]
    return [
        p for p in purls
        if p and p.type in allowed_types
    ]
