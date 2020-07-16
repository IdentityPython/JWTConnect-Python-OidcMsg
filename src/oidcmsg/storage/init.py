from .extension import LabeledDict
from .utils import importer

"""
Configuration example

STORAGE_CONFIG_1: {
    'keyjar': {
        'handler': 'abstorage.storages.abfile.AbstractFileSystem',
        'fdir': 'db/keyjar',
        'key_conv': 'abstorage.converter.QPKey',
        'value_conv': 'cryptojwt.serialize.item.KeyIssuer',
    },
    'default': {
        'handler': 'abstorage.storages.abfile.AbstractFileSystem',
        'fdir': 'db',
        'key_conv': 'abstorage.converter.QPKey',
        'value_conv': 'abstorage.converter.JSON'
    }
}
"""


class ConfigurationError(Exception):
    pass


def get_storage_conf(db_conf=None, typ='default'):
    _conf = None
    if db_conf:
        _conf = db_conf.get(typ)
        if _conf:
            return _conf
        elif typ != 'default':
            _conf = db_conf.get('default')
        else:
            raise ConfigurationError()

    return _conf


def storage_factory(configuration):
    _handler = configuration.get('handler')
    if _handler:
        storage_cls = importer(_handler)
    else:
        raise ConfigurationError('Missing handler specification')
    _conf = {k: v for k, v in configuration.items() if k != 'handler'}
    return storage_cls(_conf)


def init_storage(db_conf=None, key='default'):
    """
    Returns a storage instance.

    :param conf: Configuration
    :param key: Which part of the configuration is to be used
    """

    if db_conf:
        return storage_factory(get_storage_conf(db_conf, key))
    else:
        return LabeledDict({'label': key})
