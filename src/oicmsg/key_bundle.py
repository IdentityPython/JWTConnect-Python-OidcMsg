import json
import logging
import os
import sys
import time

import requests
from Cryptodome.PublicKey import RSA
from jwkest import as_unicode
from jwkest.jwk import ECKey
from jwkest.jwk import JWKException
from jwkest.jwk import RSAKey
from jwkest.jwk import SYMKey
from jwkest.jwk import rsa_load

from oicmsg.exception import KeyIOError
from oicmsg.exception import UnknownKeyType
from oicmsg.exception import UpdateFailed

__author__ = 'Roland Hedberg'

KEYLOADERR = "Failed to load %s key from '%s' (%s)"
REMOTE_FAILED = "Remote key update from '{}' failed, HTTP status {}"
MALFORMED = "Remote key update from {} failed, malformed JWKS."

logger = logging.getLogger(__name__)


def raise_exception(excep, descr, error='service_error'):
    _err = json.dumps({'error': error, 'error_description': descr})
    raise excep(_err, 'application/json')


K2C = {
    "RSA": RSAKey,
    "EC": ECKey,
    "oct": SYMKey,
}


def create_and_store_rsa_key_pair(name="oicmsg", path=".", size=2048):
    """
    :param name: Name of the key file
    :param path: Path to where the key files are stored
    :param size: RSA key size
    :return: RSA key
    """

    key = RSA.generate(size)

    if sys.version_info[0] > 2:
        os.makedirs(path, exist_ok=True)
    else:
        try:
            os.makedirs(path)
        except OSError:  # assume this is because it already exists
            pass

    if name:
        with open(os.path.join(path, name), 'wb') as f:
            f.write(key.exportKey('PEM'))

        _pub_key = key.publickey()
        with open(os.path.join(path, '{}.pub'.format(name)), 'wb') as f:
            f.write(_pub_key.exportKey('PEM'))

    return key


def rsa_init(spec):
    """

    :param spec:
    :return: KeyBundle
    """
    arg = {}
    for param in ["name", "path", "size"]:
        try:
            arg[param] = spec[param]
        except KeyError:
            pass

    kb = KeyBundle(keytype="RSA", keyusage=spec["use"])
    for use in spec["use"]:
        _key = create_and_store_rsa_key_pair(**arg)
        kb.append(RSAKey(use=use, key=_key))
    return kb


class KeyBundle(object):
    def __init__(self, keys=None, source="", cache_time=300, verify_ssl=True,
                 fileformat="jwk", keytype="RSA", keyusage=None):
        """

        :param keys: A list of dictionaries
            with the keys ["kty", "key", "alg", "use", "kid"]
        :param source: Where the key set can be fetch from
        :param verify_ssl: Verify the SSL cert used by the server
        :param fileformat: For a local file either "jwk" or "der"
        :param keytype: Iff local file and 'der' format what kind of key it is.
        """

        self._keys = []
        self.remote = False
        self.verify_ssl = verify_ssl
        self.cache_time = cache_time
        self.time_out = 0
        self.etag = ""
        self.source = None
        self.fileformat = fileformat.lower()
        self.keytype = keytype
        self.keyusage = keyusage
        self.imp_jwks = None
        self.last_updated = 0

        if keys:
            self.source = None
            if isinstance(keys, dict):
                self.do_keys([keys])
            else:
                self.do_keys(keys)
        else:
            if source.startswith("file://"):
                self.source = source[7:]
            elif source.startswith("http://") or source.startswith("https://"):
                self.source = source
                self.remote = True
            elif source == "":
                return
            else:
                raise KeyIOError("Unsupported source type: %s" % source)

            if not self.remote:  # local file
                if self.fileformat == "jwk":
                    self.do_local_jwk(self.source)
                elif self.fileformat == "der":  # Only valid for RSA keys
                    self.do_local_der(self.source, self.keytype, self.keyusage)

    def do_keys(self, keys):
        """
        Go from JWK description to binary keys

        :param keys:
        :return:
        """
        for inst in keys:
            typ = inst["kty"]
            flag = 0
            for _typ in [typ, typ.lower(), typ.upper()]:
                try:
                    _key = K2C[_typ](**inst)
                except KeyError:
                    continue
                except JWKException as err:
                    logger.warning('While loading keys: {}'.format(err))
                else:
                    self._keys.append(_key)
                    flag = 1
                    break
            if not flag:
                logger.warning(
                    'While loading keys, UnknownKeyType: {}'.format(typ))

    def do_local_jwk(self, filename):
        try:
            self.do_keys(json.loads(open(filename).read())["keys"])
        except KeyError:
            logger.error("Now 'keys' keyword in JWKS")
            raise_exception(
                UpdateFailed,
                "Local key update from '{}' failed.".format(filename))
        else:
            self.last_updated = time.time()

    def do_local_der(self, filename, keytype, keyusage):
        # This is only for RSA keys
        _bkey = rsa_load(filename)

        if not keyusage:
            keyusage = ["enc", "sig"]

        for use in keyusage:
            _key = RSAKey().load_key(_bkey)
            _key.use = use
            self._keys.append(_key)

        self.last_updated = time.time()

    def do_remote(self):
        args = {"verify": self.verify_ssl}
        if self.etag:
            args["headers"] = {"If-None-Match": self.etag}

        try:
            logging.debug('KeyBundle fetch keys from: {}'.format(self.source))
            r = requests.get(self.source, **args)
        except Exception as err:
            logger.error(err)
            raise_exception(UpdateFailed,
                            REMOTE_FAILED.format(self.source, str(err)))

        if r.status_code == 304:  # file has not changed
            self.time_out = time.time() + self.cache_time
            self.last_updated = time.time()
            try:
                self.do_keys(self.imp_jwks["keys"])
            except KeyError:
                logger.error("No 'keys' keyword in JWKS")
                raise_exception(UpdateFailed, "No 'keys' keyword in JWKS")
            else:
                return False
        elif r.status_code == 200:  # New content
            self.time_out = time.time() + self.cache_time

            self.imp_jwks = self._parse_remote_response(r)
            if not isinstance(self.imp_jwks,
                              dict) or "keys" not in self.imp_jwks:
                raise_exception(UpdateFailed, MALFORMED.format(self.source))

            logger.debug("Loaded JWKS: %s from %s" % (r.text, self.source))
            try:
                self.do_keys(self.imp_jwks["keys"])
            except KeyError:
                logger.error("No 'keys' keyword in JWKS")
                raise_exception(UpdateFailed, MALFORMED.format(self.source))

            try:
                self.etag = r.headers["Etag"]
            except KeyError:
                pass
        else:
            raise_exception(UpdateFailed,
                            REMOTE_FAILED.format(self.source, r.status_code))
        self.last_updated = time.time()
        return True

    def _parse_remote_response(self, response):
        """
        Parse JWKS from the HTTP response.

        Should be overriden by subclasses for adding support of e.g. signed
        JWKS.
        :param response: HTTP response from the 'jwks_uri' endpoint
        :return: response parsed as JSON
        """
        # Check if the content type is the right one.
        try:
            if response.headers["Content-Type"] != 'application/json':
                logger.warning('Wrong Content_type')
        except KeyError:
            pass

        logger.debug("Loaded JWKS: %s from %s" % (response.text, self.source))
        try:
            return json.loads(response.text)
        except ValueError:
            return None

    def _uptodate(self):
        res = False
        if self._keys is not []:
            if self.remote:  # verify that it's not to old
                if time.time() > self.time_out:
                    if self.update():
                        res = True
        elif self.remote:
            if self.update():
                res = True
        return res

    def update(self):
        """
        Reload the key if necessary
        This is a forced update, will happen even if cache time has not elapsed
        """
        res = True  # An update was successful
        if self.source:
            # reread everything
            self._keys = []

            if self.remote is False:
                if self.fileformat == "jwk":
                    self.do_local_jwk(self.source)
                elif self.fileformat == "der":
                    self.do_local_der(self.source, self.keytype, self.keyusage)
            else:
                res = self.do_remote()
        return res

    def get(self, typ=""):
        """

        :param typ: Type of key (rsa, ec, oct, ..)
        :return: If typ is undefined all the keys as a dictionary
            otherwise the appropriate keys in a list
        """
        self._uptodate()
        _typs = [typ.lower(), typ.upper()]

        if typ:
            return [k for k in self._keys if k.kty in _typs]
        else:
            return self._keys

    def keys(self):
        self._uptodate()

        return self._keys

    def available_keys(self):
        return self._keys

    def remove_key(self, typ, val=None):
        """

        :param typ: Type of key (rsa, ec, oct, ..)
        :param val: The key itself
        """
        if val:
            self._keys = [k for k in self._keys if
                          not (k.kty == typ and k.key == val.key)]
        else:
            self._keys = [k for k in self._keys if not k.kty == typ]

    def __str__(self):
        return str(self.jwks())

    def jwks(self, private=False):
        self._uptodate()
        keys = list()
        for k in self._keys:
            if private:
                key = k.serialize(private)
            else:
                key = k.to_dict()
                for k, v in key.items():
                    key[k] = as_unicode(v)
            keys.append(key)
        return json.dumps({"keys": keys})

    def append(self, key):
        self._keys.append(key)

    def remove(self, key):
        self._keys.remove(key)

    def __len__(self):
        return len(self._keys)

    def get_key_with_kid(self, kid):
        for key in self._keys:
            if key.kid == kid:
                return key

        # Try updating since there might have been an update to the key file
        self.update()

        for key in self._keys:
            if key.kid == kid:
                return key

        return None

    def kids(self):
        self._uptodate()
        return [key.kid for key in self._keys if key.kid != ""]

    def remove_outdated(self, after, when=0):
        """
        Remove keys that should not be available any more.
        Outdated means that the key was marked as inactive at a time
        that was longer ago then what is given in 'after'.

        :param after: The length of time the key will remain in the KeyBundle
            before it should be removed.
        :param when: To make it easier to test
        """
        if when:
            now = when
        else:
            now = time.time()

        if not isinstance(after, float):
            try:
                after = float(after)
            except TypeError:
                raise

        _kl = []
        for k in self._keys:
            if k.inactive_since and k.inactive_since + after < now:
                continue
            else:
                _kl.append(k)

        self._keys = _kl


def keybundle_from_local_file(filename, typ, usage):
    if typ.upper() == "RSA":
        kb = KeyBundle()
        k = RSAKey()
        k.load(filename)
        k.use = usage[0]
        kb.append(k)
        for use in usage[1:]:
            _k = RSAKey()
            _k.use = use
            _k.load_key(k.key)
            kb.append(_k)
    elif typ.lower() == "jwk":
        kb = KeyBundle(source=filename, fileformat="jwk", keyusage=usage)
    else:
        raise UnknownKeyType("Unsupported key type")

    return kb


class RedirectStdStreams(object):
    def __init__(self, stdout=None, stderr=None):
        self._stdout = stdout or sys.stdout
        self._stderr = stderr or sys.stderr

    def __enter__(self):
        self.old_stdout, self.old_stderr = sys.stdout, sys.stderr
        self.old_stdout.flush()
        self.old_stderr.flush()
        sys.stdout, sys.stderr = self._stdout, self._stderr

    def __exit__(self, exc_type, exc_value, trace_back):
        self._stdout.flush()
        self._stderr.flush()
        sys.stdout = self.old_stdout
        sys.stderr = self.old_stderr


def dump_jwks(kbl, target, private=False):
    """
    Write a JWK to a file

    :param kbl: List of KeyBundles
    :param target: Name of the file to which everything should be written
    :param private: Should also the private parts be exported
    """

    keys = []
    for kb in kbl:
        keys.extend([k.serialize(private) for k in kb.keys() if
                     k.kty != 'oct' and not k.inactive_since])
    res = {"keys": keys}

    try:
        f = open(target, 'w')
    except IOError:
        (head, tail) = os.path.split(target)
        os.makedirs(head)
        f = open(target, 'w')

    _txt = json.dumps(res)
    f.write(_txt)
    f.close()
