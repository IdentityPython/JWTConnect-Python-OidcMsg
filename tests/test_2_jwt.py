import os

from oicmsg.jwt import JWT
from oicmsg.key_jar import build_keyjar, KeyJar
from oicmsg.oic import JsonWebToken

__author__ = 'Roland Hedberg'

BASE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "data/keys"))

keys = [
    {"type": "RSA", "key": os.path.join(BASE_PATH, "cert.key"),
     "use": ["enc", "sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["enc"]}
]
jwks, keyjar, kidd = build_keyjar(keys)
issuer = 'https://fedop.example.org'
receiver = 'https://example.com'
keyjar[issuer] = keyjar['']  # just testing right !?
keyjar[receiver] = keyjar['']


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_jwt_pack():
    _jwt = JWT(keyjar, lifetime=3600, iss=issuer).pack_jwt()

    assert _jwt
    assert len(_jwt.split('.')) == 3


def test_jwt_pack_and_unpack():
    srv = JWT(keyjar, iss=issuer)
    payload = {'sub': 'sub'}
    _jwt = srv.pack_jwt(payload=payload)

    info = srv.unpack_jwt(_jwt)

    assert set(info.keys()) == {'jti', 'iat', 'iss', 'sub', 'kid'}

def test_jwt_pack_and_unpack_with_lifetime():
    srv = JWT(keyjar, iss=issuer, lifetime=600)
    payload = {'sub': 'sub'}
    _jwt = srv.pack_jwt(payload=payload)

    info = srv.unpack_jwt(_jwt)

    assert set(info.keys()) == {'jti', 'iat', 'iss', 'sub', 'kid', 'exp'}


def test_jwt_pack_encrypt():
    srv = JWT(keyjar, iss=issuer)
    payload = {'sub': 'sub', 'aud': receiver}
    _jwt = srv.pack_jwt(payload=payload, encrypt=True)

    info = srv.unpack_jwt(_jwt)

    assert isinstance(info, JsonWebToken)
    assert set(info.keys()) == {'jti', 'iat', 'iss', 'sub', 'kid', 'aud'}


def test_jwt_pack_unpack_sym():
    kj = KeyJar()
    kj.add_symmetric(owner='', key='client_secret', usage=['sig'])
    kj['https://fedop.example.org'] = kj['']
    srv = JWT(kj, iss=issuer, sign_alg="HS256")
    payload = {'sub': 'sub2'}
    _jwt = srv.pack_jwt(payload=payload)
    info = srv.unpack_jwt(_jwt)
    assert info
