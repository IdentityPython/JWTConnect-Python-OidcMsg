import copy
from urllib.parse import quote_plus

from cryptojwt import KeyJar
from cryptojwt.key_jar import init_key_jar

from oidcmsg.message import Message
from oidcmsg.storage.init import get_storage_conf
from oidcmsg.storage.init import init_storage
from oidcmsg.storage.init import storage_factory


def add_issuer(conf, issuer):
    res = {}
    for key, val in conf.items():
        if key == 'abstract_storage_cls':
            res[key] = val
        else:
            _val = copy.deepcopy(val)
            _val['issuer'] = quote_plus(issuer)
            res[key] = _val
    return res


class OidcContext:
    def __init__(self, config=None, keyjar=None, entity_id=''):
        if config is None:
            config = {}

        self.db_conf = config.get('db_conf')
        if self.db_conf:
            _iss = config.get('issuer')
            if _iss:
                self.db_conf = add_issuer(self.db_conf, _iss)

            if self.db_conf.get('default'):
                self.db = init_storage(self.db_conf)
            else:
                self.db = None
        else:
            self.db = init_storage()

        self.keyjar = self._keyjar(keyjar, self.db_conf, config, entity_id=entity_id)

    def add_boxes(self, boxes, db_conf):
        for key, attr in boxes.items():
            setattr(self, attr, init_storage(db_conf, key))

    def _keyjar(self, keyjar=None, db_conf=None, conf=None, entity_id=''):
        if keyjar is None:
            if db_conf:
                _storage = storage_factory(get_storage_conf(db_conf, 'keyjar'))
            else:
                _storage = None

            if 'keys' in conf:
                args = {k: v for k, v in conf["keys"].items() if k != "uri_path"}
                args.update({'storage': _storage})
                _keyjar = init_key_jar(**args)
            else:
                _keyjar = KeyJar(storage=_storage)
                if 'jwks' in conf:
                    _keyjar.import_jwks(conf['jwks'], '')

            if '' in _keyjar and entity_id:
                # make sure I have the keys under my own name too (if I know it)
                _keyjar.import_jwks_as_json(_keyjar.export_jwks_as_json(True, ''), entity_id)

            _httpc_params = conf.get('httpc_params')
            if _httpc_params:
                _keyjar.httpc_params = _httpc_params

            return _keyjar
        else:
            return keyjar

    def set(self, item, value):
        if isinstance(value, Message):
            self.db[item] = value.to_dict()
        else:
            self.db[item] = value

    def get(self, item):
        if item == 'seed':
            return bytes(self.db[item], 'utf-8')
        else:
            return self.db[item]
