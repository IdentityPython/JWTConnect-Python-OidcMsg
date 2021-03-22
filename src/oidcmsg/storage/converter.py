import json
from urllib.parse import quote_plus
from urllib.parse import unquote_plus


class QPKey:
    def serialize(self, str):
        return quote_plus(str)

    def deserialize(self, str):
        return unquote_plus(str)


class JSON:
    def serialize(self, item):
        return json.dumps(item)

    def deserialize(self, str):
        return json.loads(str)


class PassThru:
    def serialize(self, str):
        return str

    def deserialize(self, str):
        return str
