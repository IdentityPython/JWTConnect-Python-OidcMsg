import secrets

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
