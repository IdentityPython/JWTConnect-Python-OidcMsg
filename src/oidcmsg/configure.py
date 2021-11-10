import importlib
import json
import logging
import os
from typing import Dict
from typing import List
from typing import Optional

from oidcmsg.logging import configure_logging
from oidcmsg.util import load_yaml_config

DEFAULT_FILE_ATTRIBUTE_NAMES = ['server_key', 'server_cert', 'filename',
                                'private_path', 'public_path', 'db_file', 'jwks_file']

DEFAULT_DIR_ATTRIBUTE_NAMES = ['template_dir']


def lower_or_upper(config, param, default=None):
    res = config.get(param.lower(), default)
    if not res:
        res = config.get(param.upper(), default)
    return res


def add_path_to_filename(filename, base_path):
    if filename == "" or filename.startswith("/"):
        return filename
    else:
        return os.path.join(base_path, filename)


def add_path_to_directory_name(directory_name, base_path):
    if directory_name.startswith("/"):
        return directory_name
    elif directory_name == "":
        return "./" + directory_name
    else:
        return os.path.join(base_path, directory_name)


def add_base_path(conf: dict, base_path: str, attributes: List[str], attribute_type: str = "file"):
    for key, val in conf.items():
        if key in attributes:
            if attribute_type == "file":
                conf[key] = add_path_to_filename(val, base_path)
            else:
                conf[key] = add_path_to_directory_name(val, base_path)
        if isinstance(val, dict):
            conf[key] = add_base_path(val, base_path, attributes, attribute_type)

    return conf


def set_domain_and_port(conf: dict, uris: List[str], domain: str, port: int):
    for key, val in conf.items():
        if key in uris:
            if not val:
                continue

            if isinstance(val, list):
                _new = [v.format(domain=domain, port=port) for v in val]
            else:
                _new = val.format(domain=domain, port=port)
            conf[key] = _new
        elif isinstance(val, dict):
            conf[key] = set_domain_and_port(val, uris, domain, port)
    return conf


class Base(dict):
    """ Configuration base class """

    parameter = {}
    uris = ["issuer", "base_url"]

    def __init__(self,
                 conf: Dict,
                 base_path: str = '',
                 file_attributes: Optional[List[str]] = None,
                 dir_attributes: Optional[List[str]] = None,
                 domain: Optional[str] = "",
                 port: Optional[int] = 0,
                 ):
        dict.__init__(self)
        self._file_attributes = file_attributes or DEFAULT_FILE_ATTRIBUTE_NAMES
        self._dir_attributes = dir_attributes or DEFAULT_DIR_ATTRIBUTE_NAMES

        if base_path:
            # this adds a base path to all paths in the configuration
            if self._file_attributes:
                add_base_path(conf, base_path, self._file_attributes, "file")
            if self._dir_attributes:
                add_base_path(conf, base_path, self._dir_attributes, "dir")

        # entity info
        self.domain = domain or conf.get("domain", "127.0.0.1")
        self.port = port or conf.get("port", 80)

        self.conf = set_domain_and_port(conf, self.uris, self.domain, self.port)

    def __getattr__(self, item, default=None):
        if item in self:
            return self[item]
        else:
            return default

    def __setattr__(self, key, value):
        if key in self:
            raise KeyError('{} has already been set'.format(key))
        super(Base, self).__setitem__(key, value)

    def __setitem__(self, key, value):
        if key in self:
            raise KeyError('{} has already been set'.format(key))
        super(Base, self).__setitem__(key, value)

    def get(self, item, default=None):
        return self.__getattr__(item, default)

    def items(self):
        for key in self.keys():
            if key.startswith('__') and key.endswith('__'):
                continue
            yield key, getattr(self, key)

    def extend(self,
               conf: Dict,
               base_path: str,
               domain: str,
               port: int,
               entity_conf: Optional[List[dict]] = None,
               file_attributes: Optional[List[str]] = None,
               dir_attributes: Optional[List[str]] = None,
               ):
        for econf in entity_conf:
            _path = econf.get("path")
            _cnf = conf
            if _path:
                for step in _path:
                    _cnf = _cnf[step]
            _attr = econf["attr"]
            _cls = econf["class"]
            setattr(self, _attr,
                    _cls(_cnf, base_path=base_path, file_attributes=file_attributes,
                         domain=domain, port=port, dir_attributes=dir_attributes))

    def complete_paths(self, conf: Dict, keys: List[str], default_config: Dict, base_path: str):
        for key in keys:
            _val = conf.get(key)
            if _val is None and key in default_config:
                _val = default_config[key]
                if key in self._file_attributes:
                    _val = add_path_to_filename(_val, base_path)
                elif key in self._dir_attributes:
                    _val = add_path_to_directory_name(_val, base_path)
            if not _val:
                continue

            setattr(self, key, _val)

    def format(self, conf, base_path: str, domain: str, port: int,
               file_attributes: Optional[List[str]] = None,
               dir_attributes: Optional[List[str]] = None) -> None:
        """
        Formats parts of the configuration. That includes replacing the strings {domain} and {port}
        with the used domain and port and making references to files and directories absolute
        rather then relative. The formatting is done in place.

        :param dir_attributes:
        :param conf: The configuration part
        :param base_path: The base path used to make file/directory refrences absolute
        :param file_attributes: Attribute names that refer to files or directories.
        :param domain: The domain name
        :param port: The port used
        """
        if isinstance(conf, dict):
            if file_attributes:
                add_base_path(conf, base_path, file_attributes, attribute_type="file")
            if dir_attributes:
                add_base_path(conf, base_path, dir_attributes, attribute_type="dir")
            if isinstance(conf, dict):
                set_domain_and_port(conf, self.uris, domain=domain, port=port)


class Configuration(Base):
    """Entity Configuration Base"""
    uris = ["redirect_uris", 'issuer', 'base_url', 'server_name']

    def __init__(self,
                 conf: Dict,
                 base_path: str = '',
                 entity_conf: Optional[List[dict]] = None,
                 file_attributes: Optional[List[str]] = None,
                 domain: Optional[str] = "",
                 port: Optional[int] = 0,
                 dir_attributes: Optional[List[str]] = None,
                 ):
        Base.__init__(self, conf, base_path=base_path, file_attributes=file_attributes,
                      dir_attributes=dir_attributes, domain=domain, port=port)

        log_conf = self.conf.get('logging')
        if log_conf:
            self.logger = configure_logging(config=log_conf).getChild(__name__)
        else:
            self.logger = logging.getLogger('oidcrp')

        self.web_conf = lower_or_upper(self.conf, "webserver")

        if entity_conf:
            self.extend(conf=self.conf, base_path=base_path,
                        domain=self.domain, port=self.port, entity_conf=entity_conf,
                        file_attributes=self._file_attributes,
                        dir_attributes=self._dir_attributes)


def create_from_config_file(cls,
                            filename: str,
                            base_path: Optional[str] = '',
                            entity_conf: Optional[List[dict]] = None,
                            file_attributes: Optional[List[str]] = None,
                            domain: Optional[str] = "",
                            port: Optional[int] = 0,
                            dir_attributes: Optional[List[str]] = None
                            ):
    if filename.endswith(".yaml"):
        """Load configuration as YAML"""
        _cnf = load_yaml_config(filename)
    elif filename.endswith(".json"):
        _str = open(filename).read()
        _cnf = json.loads(_str)
    elif filename.endswith(".py"):
        head, tail = os.path.split(filename)
        tail = tail[:-3]
        module = importlib.import_module(tail)
        _cnf = getattr(module, "CONFIG")
    else:
        raise ValueError("Unknown file type")

    return cls(_cnf,
               entity_conf=entity_conf,
               base_path=base_path, file_attributes=file_attributes,
               domain=domain, port=port, dir_attributes=dir_attributes)
