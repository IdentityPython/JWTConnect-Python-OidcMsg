from typing import List
from typing import Optional

from cryptojwt.utils import importer
from cryptojwt.utils import qualified_name

from oidcmsg.impexp import ImpExp
from oidcmsg.message import Message


class DLDict(ImpExp):
    parameter = {"db": {}}

    def __init__(self, **kwargs):
        ImpExp.__init__(self)
        self.db = kwargs

    def __setitem__(self, key: str, val):
        self.db[key] = val

    def __getitem__(self, key: str):
        return self.db[key]

    def __delitem__(self, key: str):
        del self.db[key]

    def dump(self, exclude_attributes: Optional[List[str]] = None) -> dict:
        res = {}

        for k, v in self.db.items():
            _class = qualified_name(v.__class__)
            res[k] = [_class, v.dump(exclude_attributes=exclude_attributes)]

        return res

    def load(
        self, spec: dict, init_args: Optional[dict] = None, load_args: Optional[dict] = None
    ) -> "DLDict":
        if load_args:
            _kwargs = {"load_args": load_args}
            _load_args = {}
        else:
            _load_args = {}
            _kwargs = {}

        if init_args:
            _kwargs["init_args"] = init_args

        for attr, (_item_cls, _item) in spec.items():
            _cls = importer(_item_cls)

            if issubclass(_cls, ImpExp) and init_args:
                _args = {k: v for k, v in init_args.items() if k in _cls.init_args}
            else:
                _args = {}

            _x = _cls(**_args)
            _x.load(_item, **_kwargs)
            self.db[attr] = _x

        self.local_load_adjustments(**_load_args)

        return self

    def keys(self):
        return self.db.keys()

    def items(self):
        return self.db.items()

    def values(self):
        return self.db.values()

    def __contains__(self, item):
        return item in self.db

    def get(self, item, default=None):
        return self.db.get(item, default)

    def __len__(self):
        return len(self.db)


def dump_dldict(item, exclude_attributes: Optional[List[str]] = None) -> dict:
    res = {}

    for k, v in item.items():
        _class = qualified_name(v.__class__)
        if isinstance(v, Message):
            res[k] = [_class, v.to_dict()]
        else:
            res[k] = [_class, v.dump(exclude_attributes=exclude_attributes)]

    return res


def load_dldict(
    spec: dict, init_args: Optional[dict] = None, load_args: Optional[dict] = None
) -> dict:
    db = {}

    for attr, (_item_cls, _item) in spec.items():
        _class = importer(_item_cls)
        if issubclass(_class, Message):
            db[attr] = _class().from_dict(_item)
        else:
            if issubclass(_class, ImpExp) and init_args:
                _args = {k: v for k, v in init_args.items() if k in _class.init_args}
            else:
                _args = {}

            db[attr] = _class(**_args).load(_item)

    return db


def dump_class_map(item, exclude_attributes: Optional[List[str]] = None) -> dict:
    _dump = {}
    for key, val in item.items():
        if isinstance(val, str):
            _dump[key] = val
        else:
            _dump[key] = qualified_name(val)
    return _dump


def load_class_map(
    spec: dict, init_args: Optional[dict] = None, load_args: Optional[dict] = None
) -> dict:
    _item = {}
    for key, val in spec.items():
        _item[key] = importer(val)
    return _item
