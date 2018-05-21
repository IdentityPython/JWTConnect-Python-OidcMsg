from urllib.parse import urlsplit

import json
import logging
import os
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from cryptojwt import as_bytes
from cryptojwt import as_unicode
from cryptojwt import b64e
from cryptojwt import jwe
from cryptojwt import jws
from cryptojwt.jwk import DeSerializationNotPossible
from cryptojwt.jwk import ECKey
from cryptojwt.jwk import NIST2SEC
from cryptojwt.jwk import RSAKey
from cryptojwt.jwk import rsa_load
from cryptojwt.jwk import SYMKey

from oidcmsg.exception import MessageException
from oidcmsg.exception import OidcMsgError
from oidcmsg.key_bundle import create_and_store_rsa_key_pair
from oidcmsg.key_bundle import KeyBundle
from oidcmsg.key_bundle import rsa_init

__author__ = 'Roland Hedberg'

KEYLOADERR = "Failed to load %s key from '%s' (%s)"
REMOTE_FAILED = "Remote key update from '{}' failed, HTTP status {}"
MALFORMED = "Remote key update from {} failed, malformed JWKS."

logger = logging.getLogger(__name__)


def raise_exception(excep, descr, error='service_error'):
    _err = json.dumps({'error': error, 'error_description': descr})
    raise excep(_err, 'application/json')


class KeyIOError(OidcMsgError):
    pass


class UnknownKeyType(KeyIOError):
    pass


class UpdateFailed(KeyIOError):
    pass


class KeyJar(object):
    """ A keyjar contains a number of KeyBundles """

    def __init__(self, ca_certs=None, verify_ssl=True, keybundle_cls=KeyBundle,
                 remove_after=3600):
        """
        KeyJar init function
        
        :param ca_certs: CA certificates, to be used for HTTPS
        :param verify_ssl: Attempting SSL certificate verification
        :return: Keyjar instance
        """
        self.spec2key = {}
        self.issuer_keys = {}
        self.ca_certs = ca_certs
        self.verify_ssl = verify_ssl
        self.keybundle_cls = keybundle_cls
        self.remove_after = remove_after

    def __repr__(self):
        issuers = list(self.issuer_keys.keys())
        return '<KeyJar(issuers={})>'.format(issuers)

    def add_url(self, owner, url, **kwargs):
        """
        Add a set of keys by url. This method will create a 
        :py:class:`oidcmsg.key_bundle.KeyBundle` instance with the
        url as source specification. If no fileformat is given it's assumed
        that what's on the other side is a JWKS.
        
        :param owner: Who issued the keys
        :param url: Where can the key/-s be found
        :param kwargs: extra parameters for instantiating KeyBundle
        :return: A :py:class:`oidcmsg.oauth2.keybundle.KeyBundle` instance
        """

        if not url:
            raise KeyError("No jwks_uri")

        if "/localhost:" in url or "/localhost/" in url:
            kc = self.keybundle_cls(source=url, verify_ssl=False, **kwargs)
        else:
            kc = self.keybundle_cls(source=url, verify_ssl=self.verify_ssl,
                                    **kwargs)

        try:
            self.issuer_keys[owner].append(kc)
        except KeyError:
            self.issuer_keys[owner] = [kc]

        return kc

    def add_symmetric(self, owner, key, usage=None):
        """
        Add a symmetric key. This is done by wrapping it in a key bundle 
        cloak since KeyJar does not handle keys directly but only through
        key bundles.
        
        :param owner: Owner of the key
        :param key: The key 
        :param usage: What the key can be used for signing/signature 
            verification (sig) and/or encryption/decryption (enc)
        """
        if owner not in self.issuer_keys:
            self.issuer_keys[owner] = []

        _key = b64e(as_bytes(key))
        if usage is None:
            self.issuer_keys[owner].append(
                self.keybundle_cls([{"kty": "oct", "k": _key}]))
        else:
            for use in usage:
                self.issuer_keys[owner].append(
                    self.keybundle_cls([{"kty": "oct",
                                         "k": _key,
                                         "use": use}]))

    def add_kb(self, owner, kb):
        """
        Add a key bundle and bind it to an identifier
        
        :param owner: Owner of the keys in the keybundle
        :param kb: A :py:class:`oidcmsg.key_bundle.KeyBundle` instance
        """
        try:
            self.issuer_keys[owner].append(kb)
        except KeyError:
            self.issuer_keys[owner] = [kb]

    def __setitem__(self, owner, val):
        """
        Bind one or a list of key bundles to a special identifier.
        Will overwrite whatever was there before !!
        
        :param owner: The owner of the keys in the keybundle/-s
        :param val: A single or a list of KeyBundle instance
        :return: 
        """
        if not isinstance(val, list):
            val = [val]

        for kb in val:
            if not isinstance(kb, KeyBundle):
                raise ValueError('{} not an KeyBundle instance'.format(kb))

        self.issuer_keys[owner] = val

    def items(self):
        """
        Get all owner ID's and there key bundles
        
        :return: list of 2-tuples (Owner ID., list of KeyBundles)
        """
        return self.issuer_keys.items()

    def get(self, key_use, key_type="", owner="", kid=None, **kwargs):
        """
        Get all keys that matches a set of search criteria

        :param key_use: A key useful for this usage (enc, dec, sig, ver)
        :param key_type: Type of key (rsa, ec, oct, ..)
        :param owner: Who is the owner of the keys, "" == me
        :param kid: A Key Identifier
        :return: A possibly empty list of keys
        """

        if key_use in ["dec", "enc"]:
            use = "enc"
        else:
            use = "sig"

        _kj = None
        if owner != "":
            try:
                _kj = self.issuer_keys[owner]
            except KeyError:
                if owner.endswith("/"):
                    try:
                        _kj = self.issuer_keys[owner[:-1]]
                    except KeyError:
                        pass
                else:
                    try:
                        _kj = self.issuer_keys[owner + "/"]
                    except KeyError:
                        pass
        else:
            try:
                _kj = self.issuer_keys[owner]
            except KeyError:
                pass

        if _kj is None:
            return []

        lst = []
        for bundle in _kj:
            if key_type:
                _bkeys = bundle.get(key_type)
            else:
                _bkeys = bundle.keys()
            for key in _bkeys:
                if key.inactive_since and key_use != "sig":
                    # Skip inactive keys unless for signature verification
                    continue
                if not key.use or use == key.use:
                    if kid:
                        if key.kid == kid:
                            lst.append(key)
                            break
                        else:
                            continue
                    else:
                        lst.append(key)

        # if elliptic curve have to check I have a key of the right curve
        if key_type == "EC" and "alg" in kwargs:
            name = "P-{}".format(kwargs["alg"][2:])  # the type
            _lst = []
            for key in lst:
                if name != key.crv:
                    continue
                _lst.append(key)
            lst = _lst

        if use == 'enc' and key_type == 'oct' and owner != '':
            # Add my symmetric keys
            for kb in self.issuer_keys['']:
                for key in kb.get(key_type):
                    if key.inactive_since:
                        continue
                    if not key.use or key.use == use:
                        lst.append(key)

        return lst

    def get_signing_key(self, key_type="", owner="", kid=None, **kwargs):
        return self.get("sig", key_type, owner, kid, **kwargs)

    def get_verify_key(self, key_type="", owner="", kid=None, **kwargs):
        return self.get("ver", key_type, owner, kid, **kwargs)

    def get_encrypt_key(self, key_type="", owner="", kid=None, **kwargs):
        return self.get("enc", key_type, owner, kid, **kwargs)

    def get_decrypt_key(self, key_type="", owner="", kid=None, **kwargs):
        return self.get("dec", key_type, owner, kid, **kwargs)

    def keys_by_alg_and_usage(self, issuer, alg, usage):
        if usage in ["sig", "ver"]:
            ktype = jws.alg2keytype(alg)
        else:
            ktype = jwe.alg2keytype(alg)

        return self.get(usage, ktype, issuer)

    def get_issuer_keys(self, issuer):
        res = []
        for kbl in self.issuer_keys[issuer]:
            res.extend(kbl.keys())
        return res

    def __contains__(self, item):
        if item in self.issuer_keys:
            return True
        else:
            return False

    def __getitem__(self, owner):
        try:
            return self.issuer_keys[owner]
        except KeyError:
            logger.debug(
                "Owner '{}' not found, available key owners: {}".format(
                    owner, list(self.issuer_keys.keys())))
            raise

    def owners(self):
        return self.issuer_keys.keys()

    def match_owner(self, url):
        for owner in self.issuer_keys.keys():
            if url.startswith(owner):
                return owner

        raise KeyIOError("No keys for '%s'" % url)

    def __str__(self):
        _res = {}
        for _id, kbs in self.issuer_keys.items():
            _l = []
            for kb in kbs:
                _l.extend(json.loads(kb.jwks())["keys"])
            _res[_id] = {"keys": _l}
        return "%s" % (_res,)

    def load_keys(self, pcr, issuer, replace=False):
        """
        Fetch keys from another server

        :param pcr: The provider information
        :param issuer: The provider URL
        :param replace: If all previously gathered keys from this provider
            should be replace.
        :return: Dictionary with usage as key and keys as values
        """

        logger.debug("Initiating key bundle for issuer: %s" % issuer)
        try:
            logger.debug("pcr: %s" % pcr)
        except MessageException:
            pass

        if replace or issuer not in self.issuer_keys:
            self.issuer_keys[issuer] = []

        try:
            self.add_url(issuer, pcr["jwks_uri"])
        except KeyError:
            # jwks should only be considered if no jwks_uri is present
            try:
                _keys = pcr["jwks"]["keys"]
                self.issuer_keys[issuer].append(
                    self.keybundle_cls(_keys, verify_ssl=self.verify_ssl))
            except KeyError:
                pass

    def find(self, source, issuer):
        """
        Find a key bundle based on the source of the keys

        :param source: A source url
        :param issuer: The issuer of keys
        """
        try:
            for kb in self.issuer_keys[issuer]:
                if kb.source == source:
                    return kb
        except KeyError:
            return None

    def export_jwks(self, private=False, issuer=""):
        """
        Produces a dictionary that later can be easily mapped into a 
        JSON string representing a JWKS.
        
        :param private: 
        :param issuer: 
        :return: 
        """
        keys = []
        for kb in self.issuer_keys[issuer]:
            keys.extend([k.serialize(private) for k in kb.keys() if
                         k.inactive_since == 0])
        return {"keys": keys}

    def export_jwks_as_json(self, private=False, issuer=""):
        return json.dumps(self.export_jwks(private, issuer))

    def import_jwks(self, jwks, issuer):
        """

        :param jwks: Dictionary representation of a JWKS
        :param issuer: Who 'owns' the JWKS
        """
        try:
            _keys = jwks["keys"]
        except KeyError:
            raise ValueError('Not a proper JWKS')
        else:
            try:
                self.issuer_keys[issuer].append(
                    self.keybundle_cls(_keys, verify_ssl=self.verify_ssl))
            except KeyError:
                self.issuer_keys[issuer] = [self.keybundle_cls(
                    _keys, verify_ssl=self.verify_ssl)]

    def import_jwks_as_json(self, js, issuer):
        return self.import_jwks(json.loads(js), issuer)

    def __eq__(self, other):
        if not isinstance(other, KeyJar):
            return False

        # The set of issuers MUST be the same
        if set(self.owners()) != set(other.owners()):
            return False

        # Keys per issuer must be the same
        for iss in self.owners():
            sk = self.get_issuer_keys(iss)
            ok = other.get_issuer_keys(iss)
            if len(sk) != len(ok):
                return False

            if not any(k in ok for k in sk):
                return False

        return True

    def remove_outdated(self, when=0):
        """
        Goes through the complete list of issuers and for each of them removes
        outdated keys.
        Outdated keys are keys that has been marked as inactive at a time that
        is longer ago then some set number of seconds.
        The number of seconds a carried in the remove_after parameter.

        :param when: To facilitate testing
        """
        for iss in list(self.owners()):
            _kbl = []
            for kb in self.issuer_keys[iss]:
                kb.remove_outdated(self.remove_after, when=when)
                if len(kb):
                    _kbl.append(kb)
            if _kbl:
                self.issuer_keys[iss] = _kbl
            else:
                del self.issuer_keys[iss]

    def _add_key(self, keys, owner, use, key_type='', kid='',
                 no_kid_issuer=None, allow_missing_kid=False):

        if owner not in self:
            logger.error('Issuer "{}" not in keyjar'.format(owner))
            return keys

        logger.debug('Key set summary for {}: {}'.format(
            owner, key_summary(self, owner)))

        if kid:
            for _key in self.get(key_use=use, owner=owner, kid=kid,
                                 key_type=key_type):
                if _key and _key not in keys:
                    keys.append(_key)
            return keys
        else:
            try:
                kl = self.get(key_use=use, owner=owner, key_type=key_type)
            except KeyError:
                pass
            else:
                if len(kl) == 0:
                    return keys
                elif len(kl) == 1:
                    if kl[0] not in keys:
                        keys.append(kl[0])
                elif allow_missing_kid:
                    keys.extend(kl)
                elif no_kid_issuer:
                    try:
                        allowed_kids = no_kid_issuer[owner]
                    except KeyError:
                        return keys
                    else:
                        if allowed_kids:
                            keys.extend(
                                [k for k in kl if k.kid in allowed_kids])
                        else:
                            keys.extend(kl)
        return keys

    def get_jwt_decrypt_keys(self, jwt, **kwargs):
        """
        Get decryption keys from a keyjar. 
        These keys should be usable to decrypt an encrypted JWT.

        :param jwt: A cryptojwt.jwt.JWT instance
        :param kwargs: Other key word arguments
        :return: list of usable keys
        """


        try:
            _key_type = jwe.alg2keytype(jwt.headers['alg'])
        except KeyError:
            _key_type = ''

        try:
            _kid = jwt.headers['kid']
        except KeyError:
            logger.info('Missing kid')
            _kid = ''

        keys = self.get(key_use='enc', owner='', key_type=_key_type)
        keys = self._add_key(keys, '', 'enc', _key_type, _kid, {'': None})

        # Only want the private keys. Symmetric keys are also fine
        keys = [k for k in keys if k.is_private_key()]

        return keys

    def get_jwt_verify_keys(self, jwt, **kwargs):
        """
        Get keys from a keyjar. These keys should be usable to verify a 
        signed JWT.

        :param jwt: A cryptojwt.jwt.JWT instance
        :param kwargs: Other key word arguments
        :return: list of usable keys
        """

        try:
            allow_missing_kid = kwargs['allow_missing_kid']
        except KeyError:
            allow_missing_kid = False

        try:
            _key_type = jws.alg2keytype(jwt.headers['alg'])
        except KeyError:
            _key_type = ''

        try:
            _kid = jwt.headers['kid']
        except KeyError:
            logger.info('Missing kid')
            _kid = ''

        try:
            nki = kwargs['no_kid_issuer']
        except KeyError:
            nki = {}

        keys = self.get(key_use='sig', owner='', key_type=_key_type)

        _payload = jwt.payload()

        try:
            _iss = _payload['iss']
        except KeyError:
            try:
                _iss = kwargs['iss']
            except KeyError:
                _iss = ''

        if _iss:
            keys = self._add_key(keys, _iss, 'sig', _key_type,
                                 _kid, nki, allow_missing_kid)

        # First extend the keyjar if allowed
        if "jku" in jwt.headers and _iss:
            if not self.find(jwt.headers["jku"], _iss):
                # This is really questionable
                try:
                    if kwargs["trusting"]:
                        self.add_url(_iss, jwt.headers["jku"])
                except KeyError:
                    pass

        for ent in ["aud", "client_id"]:
            if ent not in _payload:
                continue
            if ent == "aud":
                # list or basestring
                if isinstance(_payload["aud"], str):
                    _aud = [_payload["aud"]]
                else:
                    _aud = _payload["aud"]
                for _e in _aud:
                    keys = self._add_key(keys, _e, 'sig', _key_type, _kid,
                                         nki, allow_missing_kid)
            else:
                keys = self._add_key(keys, _payload[ent], 'sig', _key_type,
                                     _kid, nki, allow_missing_kid)

        # Only want the public keys. Symmetric keys are also OK.
        keys = [k for k in keys if k.is_public_key()]
        return keys

    def copy(self):
        kj = KeyJar()
        for owner in self.owners():
            kj[owner] = [kb.copy() for kb in self[owner]]
        return kj


# =============================================================================


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


def key_setup(vault, **kwargs):
    """
    :param vault: Where the keys are kept
    :return: 2-tuple: result of urlsplit and a dictionary with
        parameter name as key and url and value
    """
    vault_path = proper_path(vault)

    if not os.path.exists(vault_path):
        os.makedirs(vault_path)

    kb = KeyBundle()
    for usage in ["sig", "enc"]:
        if usage in kwargs:
            if kwargs[usage] is None:
                continue

            _args = kwargs[usage]
            if _args["alg"].upper() == "RSA":
                try:
                    _key = rsa_load('%s%s' % (vault_path, "pyoidc"))
                except Exception:
                    devnull = open(os.devnull, 'w')
                    with RedirectStdStreams(stdout=devnull, stderr=devnull):
                        _key = create_and_store_rsa_key_pair(
                            path=vault_path)

                k = RSAKey(key=_key, use=usage)
                k.add_kid()
                kb.append(k)
    return kb


def key_export(baseurl, local_path, vault, keyjar, **kwargs):
    """
    :param baseurl: The base URL to which the key file names are added
    :param local_path: Where on the machine the export files are kept
    :param vault: Where the keys are kept
    :param keyjar: Where to store the exported keys
    :return: 2-tuple: result of urlsplit and a dictionary with
        parameter name as key and url and value
    """
    part = urlsplit(baseurl)

    # deal with the export directory
    if part.path.endswith("/"):
        _path = part.path[:-1]
    else:
        _path = part.path[:]

    local_path = proper_path("%s/%s" % (_path, local_path))

    if not os.path.exists(local_path):
        os.makedirs(local_path)

    kb = key_setup(vault, **kwargs)

    try:
        keyjar[""].append(kb)
    except KeyError:
        keyjar[""] = kb

    # the local filename
    _export_filename = os.path.join(local_path, "jwks")

    with open(_export_filename, "w") as f:
        f.write(str(kb))

    _url = "%s://%s%s" % (part.scheme, part.netloc,
                          _export_filename[1:])

    return _url


# ================= create RSA key ======================


def proper_path(path):
    """
    Clean up the path specification so it looks like something I could use.
    "./" <path> "/"
    """
    if path.startswith("./"):
        pass
    elif path.startswith("/"):
        path = ".%s" % path
    elif path.startswith("."):
        while path.startswith("."):
            path = path[1:]
        if path.startswith("/"):
            path = ".%s" % path
    else:
        path = "./%s" % path

    if not path.endswith("/"):
        path += "/"

    return path


def ec_init(spec):
    """
    Initiate a keybundle with an elliptic curve key. 
    
    :param spec: Key specifics of the form::
        {"type": "EC", "crv": "P-256", "use": ["sig"]}
    
    :return: A KeyBundle instance
    """

    _key = ec.generate_private_key(NIST2SEC[spec['crv']], default_backend())

    kb = KeyBundle(keytype="EC", keyusage=spec["use"])
    for use in spec["use"]:
        eck = ECKey(use=use).load_key(_key)
        kb.append(eck)
    return kb


def keyjar_init(instance, key_conf, kid_template=""):
    """
    Will add to an already existing :py:class:`oidcmsg.oauth2.Message` instance
    or create a new keyjar. As a side effekt the keyjar attribute of the 
    instance is updated.
    
    Configuration of the type::
    
        keys = [
            {"type": "RSA", "key": "cp_keys/key.pem", "use": ["enc", "sig"]},
            {"type": "EC", "crv": "P-256", "use": ["sig"]},
            {"type": "EC", "crv": "P-256", "use": ["enc"]}
        ]
    

    :param instance: server/client instance
    :param key_conf: The key configuration
    :param kid_template: A template by which to build the kids
    :return: a JWKS as a dictionary
    """

    jwks, keyjar, kdd = build_keyjar(key_conf, kid_template, instance.keyjar,
                                     instance.kid)

    instance.keyjar = keyjar
    instance.kid = kdd
    return jwks


def _new_rsa_key(spec):
    if 'name' not in spec:
        if '/' in spec['key']:
            (head, tail) = os.path.split(spec['key'])
            spec['path'] = head
            spec['name'] = tail
        else:
            spec['name'] = spec['key']
    return rsa_init(spec)


def build_keyjar(key_conf, kid_template="", keyjar=None, kidd=None):
    """
    Configuration of the type ::
    
        keys = [
            {"type": "RSA", "key": "cp_keys/key.pem", "use": ["enc", "sig"]},
            {"type": "EC", "crv": "P-256", "use": ["sig"]},
            {"type": "EC", "crv": "P-256", "use": ["enc"]}
        ]
    
    
    :param key_conf: The key configuration
    :param kid_template: A template by which to build the kids
    :return: A tuple consisting of a JWKS dictionary, a KeyJar instance
        and a representation of which kids that can be used for what.
        Note the JWKS contains private key information !!
    """

    if keyjar is None:
        keyjar = KeyJar()

    if kidd is None:
        kidd = {"sig": {}, "enc": {}}

    kid = 0
    jwks = {"keys": []}

    for spec in key_conf:
        typ = spec["type"].upper()

        if typ == "RSA":
            if "key" in spec:
                error_to_catch = (OSError, IOError,
                                  DeSerializationNotPossible)
                try:
                    kb = KeyBundle(source="file://%s" % spec["key"],
                                   fileformat="der",
                                   keytype=typ, keyusage=spec["use"])
                except error_to_catch:
                    kb = _new_rsa_key(spec)
                except Exception:
                    raise
            else:
                kb = rsa_init(spec)
        elif typ == "EC":
            kb = ec_init(spec)

        for k in kb.keys():
            if kid_template:
                k.kid = kid_template % kid
                kid += 1
            else:
                k.add_kid()
            kidd[k.use][k.kty] = k.kid

        jwks["keys"].extend(
            [k.serialize() for k in kb.keys() if k.kty != 'oct'])

        keyjar.add_kb("", kb)

    return jwks, keyjar, kidd


def update_keyjar(keyjar):
    for iss, kbl in keyjar.items():
        for kb in kbl:
            kb.update()


def key_summary(keyjar, issuer):
    try:
        kbl = keyjar[issuer]
    except KeyError:
        return ''
    else:
        key_list = []
        for kb in kbl:
            for key in kb.keys():
                if key.inactive_since:
                    key_list.append(
                        '*{}:{}:{}'.format(key.kty, key.use, key.kid))
                else:
                    key_list.append(
                        '{}:{}:{}'.format(key.kty, key.use, key.kid))
        return ', '.join(key_list)


def check_key_availability(inst, jwt):
    """
    If the server is restarted it will NOT load keys from jwks_uris for
    all the clients that has been registered. So this function is there
    to get a clients keys when needed.

    :param inst: OP instance
    :param jwt: A JWT that has to be verified or decrypted
    """

    _rj = jws.factory(jwt)
    payload = json.loads(as_unicode(_rj.jwt.part[1]))
    _cid = payload['iss']
    if _cid not in inst.keyjar:
        cinfo = inst.cdb[_cid]
        inst.keyjar.add_symmetric(_cid, cinfo['client_secret'], ['enc', 'sig'])
        inst.keyjar.add(_cid, cinfo['jwks_uri'])


def public_keys_keyjar(from_kj, origin, to_kj=None, receiver=''):
    """
    Due to cryptography's differentiating between public and private keys
    this function that constructs the public equivalent to the private key
    keyjar that build_keyjar creates.

    :param from_kj: The KeyJar instance that contains the private keys
    :param origin: The owner ID
    :param to_kj: The KeyJar that is the receiver of the public keys
    :param receiver: The owner ID under which the public keys should be stored
    :return: The modified KeyJar instance
    """

    if to_kj is None:
        to_kj = KeyJar()

    _jwks = from_kj.export_jwks(origin)
    to_kj.import_jwks(_jwks, receiver)

    return to_kj


def init_key_jar(public_path, private_path='', key_defs='', iss=''):
    """
    If a JWKS with private keys exists create a KeyJar from it.
    If not, then a set of keys are created based on the keydefs specification.
    Those keys will be stored in 2 places one with the private keys another
    with public keys. A KeyJar instance will also be instantiated with the
    newly minted keys.

    :param public_path: A file path to a file that contains a JWKS with public
        keys
    :param private_path: A file path to a file that contains a JWKS with
        private keys.
    :param key_defs: A definition of what keys should be created if they are
        not already available
    :param iss: Issuer ID
    :return: An instantiated :py:class;`oidcmsg.key_jar.KeyJar` instance
    """

    if private_path:
        if os.path.isfile(private_path):
            _jwks = open(private_path, 'r').read()
            _kj = KeyJar()
            _kj.import_jwks(json.loads(_jwks), '')
        else:
            _kj = build_keyjar(key_defs)[1]
            jwks = _kj.export_jwks(private=True)
            head, tail = os.path.split(private_path)
            if head and not os.path.isdir(head):
                os.makedirs(head)
            fp = open(private_path, 'w')
            fp.write(json.dumps(jwks))
            fp.close()

        if public_path:
            jwks = _kj.export_jwks()  # public part
            fp = open(public_path, 'w')
            fp.write(json.dumps(jwks))
            fp.close()

            if iss:
                _kj.import_jwks(jwks, iss)

    else:
        _jwks = open(public_path, 'r').read()
        _kj = KeyJar()
        _kj.import_jwks(json.loads(_jwks), '')

        if iss:
            _kj.import_jwks(json.loads(_jwks), iss)

    return _kj
