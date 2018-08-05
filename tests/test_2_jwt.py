import os
import pytest
from cryptojwt.jwk import RSAKey
from cryptojwt.jws import SignerAlgError

from oidcmsg.jwt import JWT
from oidcmsg.key_bundle import KeyBundle
from oidcmsg.key_jar import build_keyjar
from oidcmsg.key_jar import KeyJar
from oidcmsg.oidc import JsonWebToken

__author__ = 'Roland Hedberg'

BASE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "data/keys"))

keys = [
    {"type": "RSA", "key": os.path.join(BASE_PATH, "a_enc.key"),
     "use": ["enc"]},
    {"type": "RSA", "key": os.path.join(BASE_PATH, "a_sig.key"),
     "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["enc"]}
]
alice_keyjar = build_keyjar(keys)
ALICE = 'https://alice.example.org'

keys = [
    {"type": "RSA", "key": os.path.join(BASE_PATH, "b_enc.key"),
     "use": ["enc"]},
    {"type": "RSA", "key": os.path.join(BASE_PATH, "b_sig.key"),
     "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["enc"]}
]
bob_keyjar = build_keyjar(keys)
BOB = 'https://bob.example.com'

# Need to add Alice's public keys to Bob's keyjar
# and the other way around

kb = KeyBundle()

for key in alice_keyjar.get_issuer_keys(''):
    _ser = key.serialize()
    if isinstance(key, RSAKey):
        _key = RSAKey(**_ser)
        kb.append(_key)

bob_keyjar.add_kb(ALICE, kb)


kb = KeyBundle()

for key in bob_keyjar.get_issuer_keys(''):
    _ser = key.serialize()
    if isinstance(key, RSAKey):
        _key = RSAKey(**_ser)
        kb.append(_key)

alice_keyjar.add_kb(BOB, kb)

def _eq(l1, l2):
    return set(l1) == set(l2)


def test_jwt_pack():
    alice = JWT(alice_keyjar, lifetime=3600, iss=ALICE).pack()

    assert alice
    assert len(alice.split('.')) == 3


def test_jwt_pack_and_unpack():
    alice = JWT(alice_keyjar, iss=ALICE)
    payload = {'sub': 'sub'}
    _jwt = alice.pack(payload=payload)

    bob = JWT(bob_keyjar, iss=BOB)
    info = bob.unpack(_jwt)

    assert set(info.keys()) == {'iat', 'iss', 'sub', 'kid'}


def test_jwt_pack_and_unpack_with_lifetime():
    alice = JWT(alice_keyjar, iss=ALICE, lifetime=600)
    payload = {'sub': 'sub'}
    _jwt = alice.pack(payload=payload)

    bob = JWT(bob_keyjar, iss=BOB)
    info = bob.unpack(_jwt)

    assert set(info.keys()) == {'iat', 'iss', 'sub', 'kid', 'exp'}


def test_jwt_pack_encrypt():
    alice = JWT(alice_keyjar, iss=ALICE)
    payload = {'sub': 'sub', 'aud': BOB}
    _jwt = alice.pack(payload=payload, encrypt=True, recv=BOB)

    bob = JWT(bob_keyjar, iss=BOB, msg_cls=JsonWebToken)
    info = bob.unpack(_jwt)

    assert isinstance(info, JsonWebToken)
    assert set(info.keys()) == {'iat', 'iss', 'sub', 'kid', 'aud'}


def test_jwt_pack_unpack_sym():
    kj = KeyJar()
    kj.add_symmetric(owner='', key='client_secret', usage=['sig'])
    kj['https://fedop.example.org'] = kj['']

    alice = JWT(kj, iss=ALICE, sign_alg="HS256")
    payload = {'sub': 'sub2'}
    _jwt = alice.pack(payload=payload)

    kj[ALICE] = kj['']
    bob = JWT(kj, iss=BOB)
    info = bob.unpack(_jwt)
    assert info


def test_jwt_pack_and_unpack_alg_none():
    alice = JWT(alice_keyjar, iss=ALICE, sign_alg='none')
    payload = {'sub': 'sub'}
    _jwt = alice.pack(payload=payload)

    bob = JWT(bob_keyjar, iss=BOB)
    # alg = 'none' is NOT accepted
    with pytest.raises(SignerAlgError):
        bob.unpack(_jwt)
