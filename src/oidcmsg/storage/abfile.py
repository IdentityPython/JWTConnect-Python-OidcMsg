import logging
import os
import time

from filelock import FileLock

from . import Storage
from .converter import PassThru
from .converter import QPKey
from .extension import key_label
from .utils import importer

logger = logging.getLogger(__name__)


class AbstractFileSystem(Storage):
    """
    FileSystem implements a simple file based database.
    It has a dictionary like interface.
    Each key maps one-to-one to a file on disc, where the content of the
    file is the value.
    ONLY goes one level deep.
    Not directories in directories.
    """

    def __init__(self, conf_dict):
        """
        items = FileSystem(
            {
                'fdir': fdir,
                'key_conv':{'to': quote_plus, 'from': unquote_plus},
                'value_conv':{'to': keyjar_to_jwks, 'from': jwks_to_keyjar}
            })

        fdir: The root of the directory
        key_conv: Converts to/from the key displayed by this class to
            users of it to something that can be used as a file name.
            The value of key_conv is a class that has the methods 'serialize'/'deserialize'.
        value_conv: As with key_conv you can convert/translate
            the value bound to a key in the database to something that can easily
            be stored in a file. Like with key_conv the value of this parameter
            is a class that has the methods 'serialize'/'deserialize'.
        """

        super().__init__(conf_dict)
        self.config = conf_dict
        _fdir = conf_dict.get('fdir', '')
        if '{issuer}' in _fdir:
            issuer = conf_dict.get('issuer')
            if not issuer:
                raise ValueError('Missing issuer value')
            self.fdir = _fdir.format(issuer=issuer)
        else:
            self.fdir = _fdir

        self.fmtime = {}
        self.storage = {}

        key_conv = conf_dict.get('key_conv')
        if key_conv:
            self.key_conv = importer(key_conv)()
        else:
            self.key_conv = QPKey()

        value_conv = conf_dict.get('value_conv')
        if value_conv:
            self.value_conv = importer(value_conv)()
        else:
            self.value_conv = PassThru()

        if not os.path.isdir(self.fdir):
            os.makedirs(self.fdir)

        self.synch()

    def get(self, item, default=None ):
        try:
            return self[item]
        except KeyError:
            return default

    def __getitem__(self, item):
        """
        Return the value bound to an identifier.

        :param item: The identifier.
        :return:
        """
        item = self.key_conv.serialize(item)

        if self.is_changed(item):
            logger.info("File content change in {}".format(item))
            fname = os.path.join(self.fdir, item)
            self.storage[item] = self._read_info(fname)

        logger.debug('Read from "%s"', item)
        return self.storage[item]

    def __setitem__(self, key, value):
        """
        Binds a value to a specific key. If the file that the key maps to
        does not exist it will be created. The content of the file will be
        set to the value given.

        :param key: Identifier
        :param value: Value that should be bound to the identifier.
        :return:
        """

        if not os.path.isdir(self.fdir):
            os.makedirs(self.fdir, exist_ok=True)

        try:
            _key = self.key_conv.serialize(key)
        except KeyError:
            _key = key

        fname = os.path.join(self.fdir, _key)
        lock = FileLock('{}.lock'.format(fname))
        with lock:
            with open(fname, 'w') as fp:
                fp.write(self.value_conv.serialize(value))

        self.storage[_key] = value
        logger.debug('Wrote to "%s"', key)
        self.fmtime[_key] = self.get_mtime(fname)

    def __delitem__(self, key):
        fname = os.path.join(self.fdir, key)
        if os.path.isfile(fname):
            lock = FileLock('{}.lock'.format(fname))
            with lock:
                os.unlink(fname)

        try:
            del self.storage[key]
        except KeyError:
            pass

    def keys(self):
        """
        Implements the dict.keys() method
        """
        self.synch()
        for k in self.storage.keys():
            yield self.key_conv.deserialize(k)

    @staticmethod
    def get_mtime(fname):
        """
        Find the time this file was last modified.

        :param fname: File name
        :return: The last time the file was modified.
        """
        try:
            mtime = os.stat(fname).st_mtime_ns
        except OSError:
            # The file might be right in the middle of being written
            # so sleep
            time.sleep(1)
            mtime = os.stat(fname).st_mtime_ns

        return mtime

    def is_changed(self, item):
        """
        Find out if this item has been modified since last

        :param item: A key
        :return: True/False
        """
        fname = os.path.join(self.fdir, item)
        if os.path.isfile(fname):
            mtime = self.get_mtime(fname)

            try:
                _ftime = self.fmtime[item]
            except KeyError:  # Never been seen before
                self.fmtime[item] = mtime
                return True

            if mtime > _ftime:  # has changed
                self.fmtime[item] = mtime
                return True
            else:
                return False
        else:
            logger.error('Could not access {}'.format(fname))
            raise KeyError(item)

    def _read_info(self, fname):
        if os.path.isfile(fname):
            try:
                lock = FileLock('{}.lock'.format(fname))
                with lock:
                    info = open(fname, 'r').read().strip()
                return self.value_conv.deserialize(info)
            except Exception as err:
                logger.error(err)
                raise
        else:
            logger.error('No such file: {}'.format(fname))
        return None

    def synch(self):
        """
        Goes through the directory and builds a local cache based on
        the content of the directory.
        """
        if not os.path.isdir(self.fdir):
            os.makedirs(self.fdir)
            # raise ValueError('No such directory: {}'.format(self.fdir))
        for f in os.listdir(self.fdir):
            fname = os.path.join(self.fdir, f)

            if not os.path.isfile(fname):
                continue
            if fname.endswith('.lock'):
                continue

            if f in self.fmtime:
                if self.is_changed(f):
                    self.storage[f] = self._read_info(fname)
            else:
                mtime = self.get_mtime(fname)
                try:
                    self.storage[f] = self._read_info(fname)
                except Exception as err:
                    logger.warning('Bad content in {} ({})'.format(fname, err))
                else:
                    self.fmtime[f] = mtime

    def items(self):
        """
        Implements the dict.items() method
        """
        self.synch()
        for k, v in self.storage.items():
            yield self.key_conv.deserialize(k), v

    def clear(self):
        """
        Completely resets the database. This means that all information in
        the local cache and on disc will be erased.
        """
        if not os.path.isdir(self.fdir):
            os.makedirs(self.fdir, exist_ok=True)
            return

        for f in os.listdir(self.fdir):
            del self[f]

    def update(self, ava):
        """
        Replaces what's in the database with a set of key, value pairs.
        Only data bound to keys that appear in ava will be affected.

        :param ava: Dictionary
        """
        for key, val in ava.items():
            self[key] = val

    def __contains__(self, item):
        return self.key_conv.serialize(item) in self.storage

    def __iter__(self):
        return self.items()

    def __call__(self, *args, **kwargs):
        return [self.key_conv.deserialize(k) for k in self.storage.keys()]

    def __len__(self):
        if not os.path.isdir(self.fdir):
            return 0

        n = 0
        for f in os.listdir(self.fdir):
            fname = os.path.join(self.fdir, f)

            if not os.path.isfile(fname):
                continue
            if fname.endswith('.lock'):
                continue

            n += 1
        return n

    def __str__(self):
        return '{config:' + str(self.config) + ', info:' + str(self.storage) + '}'

class LabeledAbstractFileSystem(Storage):
    def __init__(self, conf_dict, label=''):
        _conf = {k: v for k, v in conf_dict.items() if k != 'label'}
        Storage.__init__(self, conf_dict=_conf)

        self.storage = AbstractFileSystem(conf_dict)
        _label = label or conf_dict.get('label', '')

        if not _label:
            self.label = ''
        else:
            self.label = '__{}__'.format(_label)

    @key_label
    def get(self, k, default=None):
        return self.storage.get(k, default)

    @key_label
    def update(self, ava):
        return self.storage.update(ava)

    @key_label
    def __getitem__(self, k):
        return self.storage.get(k)

    @key_label
    def __setitem__(self, k, v):
        self.storage[k] = v

    @key_label
    def __delitem__(self, k):
        del self.storage[k]

    @key_label
    def __contains__(self, k):
        return self.storage.__contains__(k)

    def __iter__(self):
        for key, val in self.storage.__iter__():
            if key.startswith(self.label):
                yield key[len(self.label):], val

    def keys(self):
        return [k[len(self.label):] for k in self.storage.keys() if k.startswith(self.label)]

    def items(self):
        for key, val in self.storage.__iter__():
            if key.startswith(self.label):
                yield key[len(self.label):], val

    def __len__(self):
        if not os.path.isdir(self.storage.fdir):
            return 0

        n = 0
        for f in os.listdir(self.storage.fdir):
            if f.startswith(self.label):
                fname = os.path.join(self.storage.fdir, f)

                if not os.path.isfile(fname):
                    continue
                if fname.endswith('.lock'):
                    continue

                n += 1
        return n
