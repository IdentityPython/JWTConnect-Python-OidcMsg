import importlib


def modsplit(name):
    """Split importable"""
    if ':' in name:
        _part = name.split(':')
        if len(_part) != 2:
            raise ValueError("Syntax error: {s}")
        return _part[0], _part[1]

    _part = name.split('.')
    if len(_part) < 2:
        raise ValueError("Syntax error: {s}")

    return '.'.join(_part[:-1]), _part[-1]


def importer(name):
    """Import by name"""
    _part = modsplit(name)
    module = importlib.import_module(_part[0])
    return getattr(module, _part[1])


def qualified_name(cls):
    """ Go from class instance to name usable for imports. """
    return cls.__module__ + "." + cls.__name__
