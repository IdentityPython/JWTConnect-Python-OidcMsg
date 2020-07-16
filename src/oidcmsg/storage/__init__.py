import logging

from .utils import importer

logger = logging.getLogger(__name__)


class Storage(object):
    """
    Offers a standard set of methods and I/O on persistent data.
    """

    def __init__(self, conf_dict=None):
        pass

    def get(self, k, default=None):
        raise NotImplemented()

    def update(self, ava):
        raise NotImplemented()

    def delete(self, k, v):
        raise NotImplemented()

    def __getitem__(self, k):
        raise NotImplemented()

    def __setitem__(self, k, v):
        raise NotImplemented()

    def __delitem__(self, v):
        raise NotImplemented()

    def __call__(self):
        raise NotImplemented()

    def __len__(self):
        raise NotImplemented()

    def __contains__(self, k):
        raise NotImplemented()

    def __iter__(self):
        raise NotImplemented()

    def synch(self):
        raise NotImplemented()

    def keys(self):
        raise NotImplemented()

