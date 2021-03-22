from typing import List
from typing import Optional

from cryptojwt.utils import importer
from cryptojwt.utils import qualified_name

from oidcmsg.message import Message


class ImpExp:
    parameter = {}

    def __init__(self):
        pass

    def _dump(self, cls, item, exclude_attributes: Optional[List[str]] = None) -> dict:
        if cls in [None, "", [], {}]:
            val = item
        elif isinstance(item, Message):
            val = {qualified_name(item.__class__): item.to_dict()}
        elif cls == object:
            val = qualified_name(item)
        elif isinstance(cls, list):
            val = [self._dump(cls[0], v, exclude_attributes) for v in item]
        else:
            val = item.dump(exclude_attributes=exclude_attributes)

        return val

    def dump(self, exclude_attributes: Optional[List[str]] = None) -> dict:
        _exclude_attributes = exclude_attributes or []
        info = {}
        for attr, cls in self.parameter.items():
            if attr in _exclude_attributes:
                continue

            item = getattr(self, attr, None)
            if item is None:
                continue

            info[attr] = self._dump(cls, item, exclude_attributes)

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
