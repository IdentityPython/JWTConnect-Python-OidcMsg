import os

from oicmsg.jwt import JWT
from oicmsg.key_jar import build_keyjar
from oicmsg.oic import JasonWebToken

__author__ = 'Roland Hedberg'


BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "data/keys"))

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
    _jwt = JWT(keyjar, lifetime=3600, iss=issuer).pack()

    assert _jwt
    assert len(_jwt.split('.')) == 3


def test_jwt_pack_and_unpack():
    srv = JWT(keyjar, iss=issuer)
    _jwt = srv.pack(sub='sub')

    info = srv.unpack(_jwt)

    assert _eq(info.keys(), ['jti', 'iat', 'exp', 'iss', 'sub', 'kid'])


def test_jwt_pack_encrypt():
    srv = JWT(keyjar, iss=issuer)
    _jwt = srv.pack(sub='sub', encrypt=True, aud=receiver)

    info = srv.unpack(_jwt)

    assert isinstance(info, JasonWebToken)
    assert _eq(info.keys(), ['jti', 'iat', 'exp', 'iss', 'sub', 'kid', 'aud'])
