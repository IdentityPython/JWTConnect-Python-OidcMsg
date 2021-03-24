from typing import List
from typing import Optional

from oidcmsg.impexp import ImpExp
from oidcmsg.storage import importer
from oidcmsg.storage.utils import qualified_name


class DLDict(ImpExp):
    parameter = {
        "item_class": "",
        "db": {}
    }

    def __init__(self):
        ImpExp.__init__(self)
        self.db = {}

    def __setitem__(self, key: str, val):
        self.db[key] = val

    def __getitem__(self, key: str):
        return self.db[key]

    def dump(self, exclude_attributes: Optional[List[str]] = None) -> dict:
        res = {}

        for k,v in self.db.items():
            _class = qualified_name(v.__class__)
            res[k] = [_class, v.dump(exclude_attributes=exclude_attributes)]

        return res

    def load(self, spec: dict, **kwargs) -> "DLDict":
        for attr, (_item_cls, _item) in spec.items():
            self.db[attr] = importer(_item_cls)(**kwargs).load(_item)
        return self

    def keys(self):
        return self.db.keys()

    def items(self):
        return self.db.items()
