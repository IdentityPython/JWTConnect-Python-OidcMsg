from .extension import LabeledDict
from .utils import importer


"""
Configuration examples

STORAGE_CONFIG_1: {
    'abstract_storage_cls': 'abstorage.extension.LabeledAbstractStorage',
    'keyjar': {
        'handler': 'abstorage.storages.abfile.AbstractFileSystem',
        'fdir': 'db/keyjar',
        'key_conv': 'abstorage.converter.QPKey',
        'value_conv': 'cryptojwt.serialize.item.KeyIssuer',
        'label': 'keyjar'
    },
    'default': {
        'handler': 'abstorage.storages.abfile.AbstractFileSystem',
        'fdir': 'db',
        'key_conv': 'abstorage.converter.QPKey',
        'value_conv': 'abstorage.converter.JSON'
    }
}

ABS_STORAGE_SQLALCHEMY = dict(
    driver='sqlalchemy',
    url='sqlite:///:memory:',
    params=dict(table='Thing'),
    handler=AbstractStorageSQLAlchemy
)

STORAGE_CONFIG_2 = {
    'abstract_storage_cls': 'abstorage.base.AbstractStorage',
    'default': ABS_STORAGE_SQLALCHEMY
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


def get_storage_class(db_conf):
    return importer(db_conf.get('abstract_storage_cls'))


def init_storage(db_conf=None, key='default'):
    """
    Returns a storage instance.

    :param conf: Configuration
    :param key: Which part of the configuration is to be used
    """

    if db_conf:
        storage_cls = get_storage_class(db_conf)
        return storage_cls(get_storage_conf(db_conf, key))
    else:
        return LabeledDict(key)
