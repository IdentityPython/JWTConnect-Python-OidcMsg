import json
import secrets
from urllib.parse import quote_plus
from urllib.parse import unquote_plus

import yaml


def rndstr(size=16):
    """
    Returns a string of random url safe characters

    :param size: The length of the string
    :return: string
    """
    return secrets.token_urlsafe(size)


def load_yaml_config(filename):
    """Load a YAML configuration file."""
    with open(filename, "rt", encoding='utf-8') as file:
        config_dict = yaml.safe_load(file)
    return config_dict


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
