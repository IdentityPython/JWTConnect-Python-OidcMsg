from urllib.parse import parse_qs
from urllib.parse import urlparse

import json
import pytest

from cryptojwt.jwk import SYMKey

from oidcmsg.key_jar import build_keyjar, public_keys_keyjar, KeyJar
from oidcmsg.message import json_deserializer
from oidcmsg.message import json_serializer
from oidcmsg.message import OPTIONAL_LIST_OF_MESSAGES
from oidcmsg.message import OPTIONAL_LIST_OF_STRINGS
from oidcmsg.message import OPTIONAL_MESSAGE
from oidcmsg.message import REQUIRED_LIST_OF_STRINGS
from oidcmsg.message import SINGLE_OPTIONAL_INT
from oidcmsg.message import SINGLE_OPTIONAL_JSON
from oidcmsg.message import SINGLE_OPTIONAL_STRING
from oidcmsg.message import SINGLE_REQUIRED_STRING
from oidcmsg.message import sp_sep_list_deserializer

from oidcmsg.oauth2 import Message

__author__ = 'Roland Hedberg'

keys = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "RSA", "use": ["enc"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["enc"]},
]

keym = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "RSA", "use": ["sig"]},
    {"type": "RSA", "use": ["sig"]},
]

KEYJAR = build_keyjar(keys)[1]
PUBLIC_KEYJAR = public_keys_keyjar(KEYJAR, '')

IKEYJAR = build_keyjar(keys)[1]
IKEYJAR.issuer_keys['issuer'] = IKEYJAR.issuer_keys['']
del IKEYJAR.issuer_keys['']

KEYJARS = {}
for iss in ['A', 'B', 'C']:
    _kj = build_keyjar(keym)[1]
    _kj.issuer_keys[iss] = _kj.issuer_keys['']
    del _kj.issuer_keys['']
    KEYJARS[iss] = _kj


def url_compare(url1, url2):
    url1 = urlparse(url1)
    url2 = urlparse(url2)

    if url1.scheme != url2.scheme:
        return False
    if url1.netloc != url2.netloc:
        return False
    if url1.path != url2.path:
        return False
    if not query_string_compare(url1.query, url2.query):
        return False
    if not query_string_compare(url1.fragment, url2.fragment):
        return False

    return True


def query_string_compare(query_str1, query_str2):
    return parse_qs(query_str1) == parse_qs(query_str2)


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_sp_sep_list_deserializer():
    vals = sp_sep_list_deserializer("foo bar zen")
    assert len(vals) == 3
    assert _eq(vals, ["foo", "bar", "zen"])

    vals = sp_sep_list_deserializer(["foo bar zen"])
    assert len(vals) == 3
    assert _eq(vals, ["foo", "bar", "zen"])


def test_json_serializer():
    val = json_serializer({"foo": ["bar", "stool"]})
    val_obj = json.loads(val)
    assert val_obj == {"foo": ["bar", "stool"]}


def test_json_deserializer():
    _dict = {"foo": ["bar", "stool"]}
    val = json_serializer(_dict)

    sdict = json_deserializer(val)
    assert _dict == sdict


class DummyMessage(Message):
    c_param = {
        "req_str": SINGLE_REQUIRED_STRING,
        "opt_str": SINGLE_OPTIONAL_STRING,
        "opt_int": SINGLE_OPTIONAL_INT,
        "opt_str_list": OPTIONAL_LIST_OF_STRINGS,
        "req_str_list": REQUIRED_LIST_OF_STRINGS,
        "opt_json": SINGLE_OPTIONAL_JSON
    }


class TestMessage(object):
    def test_json_serialization(self):
        item = DummyMessage(req_str="Fair", opt_str="game", opt_int=9,
                            opt_str_list=["one", "two"],
                            req_str_list=["spike", "lee"],
                            opt_json='{"ford": "green"}')

        jso = item.serialize(method="json")
        item2 = DummyMessage().deserialize(jso, "json")
        assert _eq(item2.keys(),
                   ['opt_str', 'req_str', 'opt_json', 'req_str_list',
                    'opt_str_list', 'opt_int'])

    def test_from_dict(self):
        _dict = {"req_str": "Fair", "req_str_list": ["spike", "lee"],
                 "opt_int": 9}
        _msg = DummyMessage()
        _msg.from_dict(_dict)
        assert set(_msg.keys()) == set(_dict.keys())

    def test_from_dict_lang_tag_unknown_key(self):
        _dict = {"req_str": "Fair", "req_str_list": ["spike", "lee"],
                 "opt_int": 9, 'attribute#se': 'value' }
        _msg = DummyMessage()
        _msg.from_dict(_dict)
        assert set(_msg.keys()) == set(_dict.keys())

    def test_from_dict_lang_tag(self):
        _dict = {"req_str#se": "Fair", "req_str_list": ["spike", "lee"],
                 "opt_int": 9}
        _msg = DummyMessage()
        _msg.from_dict(_dict)
        assert set(_msg.keys()) == set(_dict.keys())

    def test_from_json(self):
        jso = '{"req_str": "Fair", "req_str_list": ["spike", "lee"], ' \
              '"opt_int": 9}'
        item = DummyMessage().deserialize(jso, "json")

        assert _eq(item.keys(), ['req_str', 'req_str_list', 'opt_int'])
        assert item["opt_int"] == 9

    def test_single_optional(self):
        jso = '{"req_str": "Fair", "req_str_list": ["spike", "lee"], ' \
              '"opt_int": [9, 10]}'
        with pytest.raises(ValueError):
            DummyMessage().deserialize(jso, "json")

    def test_extra_param(self):
        jso = '{"req_str": "Fair", "req_str_list": ["spike", "lee"], "extra": ' \
              '' \
              '"out"}'
        item = DummyMessage().deserialize(jso, "json")

        assert _eq(item.keys(), ['req_str', 'req_str_list', 'extra'])
        assert item["extra"] == "out"

    def test_to_from_jwt(self):
        item = DummyMessage(req_str="Fair", opt_str="game", opt_int=9,
                            opt_str_list=["one", "two"],
                            req_str_list=["spike", "lee"],
                            opt_json='{"ford": "green"}')
        keyjar = KeyJar()
        keyjar.add_symmetric('', b"A1B2C3D4")
        jws = item.to_jwt(key=keyjar.get_signing_key('oct'),
                          algorithm="HS256")

        jitem = DummyMessage().from_jwt(jws, keyjar)

        assert _eq(jitem.keys(), ['opt_str', 'req_str', 'opt_json',
                                  'req_str_list', 'opt_str_list', 'opt_int'])

    def test_to_from_jwe(self):
        msg = DummyMessage(req_str="Fair", opt_str="game", opt_int=9,
                           opt_str_list=["one", "two"],
                           req_str_list=["spike", "lee"],
                           opt_json='{"ford": "green"}')
        keys = [SYMKey(key="A1B2C3D4")]
        jwe = msg.to_jwe(keys, alg="A128KW", enc="A128CBC-HS256")

        jitem = DummyMessage().from_jwe(jwe, keys=keys)

        assert _eq(jitem.keys(), ['opt_str', 'req_str', 'opt_json',
                                  'req_str_list', 'opt_str_list', 'opt_int'])

    def test_to_jwe_from_jwt(self):
        msg = DummyMessage(req_str="Fair", opt_str="game", opt_int=9,
                           opt_str_list=["one", "two"],
                           req_str_list=["spike", "lee"],
                           opt_json='{"ford": "green"}')
        keys = [SYMKey(key="A1B2C3D4")]
        jwe = msg.to_jwe(keys, alg="A128KW", enc="A128CBC-HS256")

        keyjar = KeyJar()
        keyjar.add_symmetric('', 'A1B2C3D4')
        jitem = DummyMessage().from_jwt(jwe, keyjar)

        assert _eq(jitem.keys(), ['opt_str', 'req_str', 'opt_json',
                                  'req_str_list', 'opt_str_list', 'opt_int'])

    def test_verify(self):
        _dict = {"req_str": "Fair", "opt_str": "game", "opt_int": 9,
                 "opt_str_list": ["one", "two"],
                 "req_str_list": ["spike", "lee"],
                 "opt_json": '{"ford": "green"}'}

        cls = DummyMessage(**_dict)
        assert cls.verify()
        assert _eq(cls.keys(), ['opt_str', 'req_str', 'opt_json',
                                'req_str_list', 'opt_str_list', 'opt_int'])

        _dict = {"req_str": "Fair", "opt_str": "game", "opt_int": 9,
                 "opt_str_list": ["one", "two"],
                 "req_str_list": ["spike", "lee"],
                 "opt_json": '{"ford": "green"}', "extra": "internal"}

        cls = DummyMessage(**_dict)
        assert cls.verify()
        assert _eq(cls.keys(), ['opt_str', 'req_str', 'extra', 'opt_json',
                                'req_str_list', 'opt_str_list', 'opt_int'])

        _dict = {"req_str": "Fair", "opt_str": "game", "opt_int": 9,
                 "opt_str_list": ["one", "two"],
                 "req_str_list": ["spike", "lee"]}

        cls = DummyMessage(**_dict)
        cls.verify()
        assert _eq(cls.keys(), ['opt_str', 'req_str', 'req_str_list',
                                'opt_str_list', 'opt_int'])

    def test_request(self):
        req = DummyMessage(req_str="Fair",
                           req_str_list=["game"]).request("http://example.com")
        assert url_compare(req,
                           "http://example.com?req_str=Fair&req_str_list=game")

    def test_get(self):
        _dict = {"req_str": "Fair", "opt_str": "game", "opt_int": 9,
                 "opt_str_list": ["one", "two"],
                 "req_str_list": ["spike", "lee"],
                 "opt_json": '{"ford": "green"}'}

        cls = DummyMessage(**_dict)

        assert cls.get("req_str") == "Fair"
        assert cls.get("opt_int", 8) == 9
        assert cls.get("missing") is None
        assert cls.get("missing", []) == []

    def test_int_instead_of_string(self):
        with pytest.raises(ValueError):
            DummyMessage(req_str=2, req_str_list=['foo'])


@pytest.mark.parametrize("keytype,alg", [
    ('RSA', 'RS256'),
    ('EC', 'ES256')
])
def test_to_jwt(keytype, alg):
    msg = Message(a='foo', b='bar', c='tjoho')
    _jwt = msg.to_jwt(KEYJAR.get_signing_key(keytype, ''), alg)
    msg1 = Message().from_jwt(_jwt, PUBLIC_KEYJAR)
    assert msg1 == msg


@pytest.mark.parametrize("keytype,alg,enc", [
    ('RSA', 'RSA1_5', 'A128CBC-HS256'),
    ('EC', 'ECDH-ES', 'A128GCM'),
])
def test_to_jwe(keytype, alg, enc):
    msg = Message(a='foo', b='bar', c='tjoho')
    _jwe = msg.to_jwe(PUBLIC_KEYJAR.get_encrypt_key(keytype, ''), alg=alg, enc=enc)
    msg1 = Message().from_jwe(_jwe, KEYJAR.get_encrypt_key(keytype, ''))
    assert msg1 == msg


def test_to_dict_with_message_obj():
    content = Message(a={'a': {'foo': {'bar': [{'bat': []}]}}})
    _dict = content.to_dict(lev=0)
    content_fixture = {'a': {'a': {'foo': {'bar': [{'bat': []}]}}}}
    assert _dict == content_fixture


def test_to_dict_with_raw_types():
    msg = Message(c_default=[])
    content_fixture = {'c_default': []}
    _dict = msg.to_dict(lev=1)
    assert _dict == content_fixture


def test_msg_deserializer():
    class MsgMessage(Message):
        c_param = {
            "msg": OPTIONAL_MESSAGE,
            "opt_str": SINGLE_OPTIONAL_STRING,
        }

    _dict = {"req_str": "Fair", "req_str_list": ["spike", "lee"],
             "opt_int": 9}
    _msg = DummyMessage()
    _msg.from_dict(_dict)

    msg = MsgMessage()
    msg['msg'] = _msg
    msg['opt_str'] = 'string'

    mjson = msg.to_json()
    mm = MsgMessage().from_json(mjson)

    assert mm['opt_str'] == 'string'
    assert set(mm['msg'].keys()) == set(_msg.keys())


def test_msg_list_deserializer():
    class MsgMessage(Message):
        c_param = {
            "msgs": OPTIONAL_LIST_OF_MESSAGES,
            "opt_str": SINGLE_OPTIONAL_STRING,
        }

    _dict = {"req_str": "Fair", "req_str_list": ["spike", "lee"],
             "opt_int": 9}
    _msg = DummyMessage()
    _msg.from_dict(_dict)

    msg = MsgMessage()
    msg['msgs'] = [_msg]
    msg['opt_str'] = 'string'

    mjson = msg.to_json()
    mm = MsgMessage().from_json(mjson)

    assert mm['opt_str'] == 'string'
    assert len(mm['msgs']) == 1
    assert set(mm['msgs'][0].keys()) == set(_msg.keys())


def test_msg_list_deserializer_dict():
    class MsgMessage(Message):
        c_param = {
            "msgs": OPTIONAL_LIST_OF_MESSAGES,
            "opt_str": SINGLE_OPTIONAL_STRING,
        }

    _dict = {"req_str": "Fair", "req_str_list": ["spike", "lee"],
             "opt_int": 9}

    msg = MsgMessage()
    msg['msgs'] = _dict
    msg['opt_str'] = 'string'

    mjson = msg.to_json()
    mm = MsgMessage().from_json(mjson)

    assert mm['opt_str'] == 'string'
    assert len(mm['msgs']) == 1
    assert set(mm['msgs'][0].keys()) == set(_dict.keys())
