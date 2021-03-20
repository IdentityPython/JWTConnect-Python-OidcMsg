import copy
from typing import Optional
from urllib.parse import quote_plus

from cryptojwt.utils import importer
from cryptojwt.utils import qualified_name

from oidcmsg.message import Message


def add_issuer(conf, issuer):
    res = {}
    for key, val in conf.items():
        if key == 'abstract_storage_cls':
            res[key] = val
        else:
            _val = copy.copy(val)
            _val['issuer'] = quote_plus(issuer)
            res[key] = _val
    return res


class ImpExp:
    parameter = {}

    def __init__(self):
        pass

    def _dump(self, cls, item, cutoff: Optional[list] = None):
        if cls in [None, "", [], {}]:
            val = item
        elif isinstance(item, Message):
            val = {qualified_name(item.__class__): item.to_dict()}
        elif cls == object:
            val = qualified_name(item)
        elif isinstance(cls, list):
            val = [self._dump(cls[0], v, cutoff) for v in item]
        else:
            val = item.dump(cutoff=cutoff)

        return val

    def dump(self, cutoff: Optional[list] = None) -> dict:
        _cutoff = cutoff or []
        info = {}
        for attr, cls in self.parameter.items():
            if attr in _cutoff:
                continue

            item = getattr(self, attr, None)
            if item is None:
                continue

            info[attr] = self._dump(cls, item, cutoff)

        return info

    def _local_adjustments(self):
        pass

    def _load(self, cls, item):
        if cls in [None, "", [], {}]:
            val = item
        elif cls == object:
            val = importer(item)
        elif isinstance(cls, list):
            val = [cls[0]().load(v) for v in item]
        elif issubclass(cls, Message):
            val = cls().from_dict(item)
        else:
            val = cls().load(item)

        return val

    def load(self, item: dict):
        for attr, cls in self.parameter.items():
            if attr not in item:
                continue

            setattr(self, attr, self._load(cls, item[attr]))

        self._local_adjustments()
        return self

    def flush(self):
        """
        Reset the content of the instance to its pristine state

        :return: A reference to the instance itself
        """
        for attr, cls in self.parameter.items():
            if cls is None:
                setattr(self, attr, None)
            elif cls == "":
                setattr(self, attr, "")
            elif cls == []:
                setattr(self, attr, [])
            elif cls == {}:
                setattr(self, attr, {})
            else:
                setattr(self, attr, None)
        return self
