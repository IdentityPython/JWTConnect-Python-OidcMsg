import json
import secrets
from urllib.parse import parse_qs
from urllib.parse import quote_plus
from urllib.parse import unquote_plus
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

from cryptojwt.utils import importer
import yaml


def rndstr(size=16):
    """
    Returns a string of random url safe characters

    :param size: The length of the string
    :return: string
    """
    return secrets.token_urlsafe(size)


def instantiate(cls, **kwargs):
    if isinstance(cls, str):
        return importer(cls)(**kwargs)
    else:
        return cls(**kwargs)


def sanitize(str):
    return str


def load_yaml_config(filename):
    """Load a YAML configuration file."""
    with open(filename, "rt", encoding='utf-8') as file:
        config_dict = yaml.safe_load(file)
    return config_dict


# def split_uri(uri):
#     p = urlsplit(uri)
#
#     if p.fragment:
#         p = p._replace(fragment="")
#
#     if p.query:
#         o = p._replace(query="")
#         base = urlunsplit(o)
#         return base, parse_qs(p.query)
#     else:
#         base = urlunsplit(p)
#         return base, ""


# Converters

class QPKey:
    def serialize(self, str):
        return quote_plus(str)

    def deserialize(self, str):
        return unquote_plus(str)


class JSON:
    def serialize(self, str):
        return json.dumps(str)

    def deserialize(self, str):
        return json.loads(str)


class PassThru:
    def serialize(self, str):
        return str

    def deserialize(self, str):
        return str


def get_http_params(config):
    params = config.get("httpc_params", {})

    if "verify" not in params:
        _ver = config.get('verify')
        if _ver is None:
            _ver = config.get('verify_ssl', True)
        params["verify"] = _ver

    _cert = config.get('client_cert')
    _key = config.get('client_key')
    if _cert:
        if _key:
            params['cert'] = (_cert, _key)
        else:
            params['cert'] = _cert

    return params


def add_path(url, path):
    if url.endswith('/'):
        if path.startswith('/'):
            return '{}{}'.format(url, path[1:])
        else:
            return '{}{}'.format(url, path)
    else:
        if path.startswith('/'):
            return '{}{}'.format(url, path)
        else:
            return '{}/{}'.format(url, path)
