# -*- coding: utf-8 -*-
import time
import json
import os
import pytest
import sys

from urllib.parse import parse_qs
from urllib.parse import urlencode

from cryptojwt.exception import BadSignature
from cryptojwt.jws import alg2keytype

from oidcmsg import time_util
from oidcmsg.exception import MissingRequiredAttribute
from oidcmsg.exception import NotAllowedValue
from oidcmsg.exception import WrongSigningAlgorithm
from oidcmsg.key_bundle import KeyBundle
from oidcmsg.key_jar import KeyJar
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import CheckSessionRequest
from oidcmsg.oidc import ClaimsRequest
from oidcmsg.oidc import DiscoveryRequest
from oidcmsg.oidc import factory
from oidcmsg.oidc import msg_ser_json
from oidcmsg.oidc import AccessTokenResponse
from oidcmsg.oidc import AuthnToken
from oidcmsg.oidc import AuthorizationErrorResponse
from oidcmsg.oidc import AuthorizationResponse
from oidcmsg.oidc import EndSessionRequest
from oidcmsg.oidc import EndSessionResponse
from oidcmsg.oidc import AddressClaim
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.oidc import Claims
from oidcmsg.oidc import IdToken
from oidcmsg.oidc import JRD
from oidcmsg.oidc import Link
from oidcmsg.oidc import OpenIDSchema
from oidcmsg.oidc import ProviderConfigurationResponse
from oidcmsg.oidc import RegistrationRequest
from oidcmsg.oidc import RegistrationResponse
from oidcmsg.oidc import address_deser
from oidcmsg.oidc import claims_deser
from oidcmsg.oidc import claims_ser
from oidcmsg.oidc import msg_ser
from oidcmsg.oidc import scope2claims
from oidcmsg.time_util import utc_time_sans_frac

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),
                                             '..', '..')))

__author__ = 'Roland Hedberg'

CLIENT_ID = "client_1"
IDTOKEN = IdToken(iss="http://oic.example.org/", sub="sub",
                  aud=CLIENT_ID, exp=utc_time_sans_frac() + 300,
                  nonce="N0nce", iat=time.time())
KC_SYM_S = KeyBundle(
    {"kty": "oct", "key": "abcdefghijklmnop".encode("utf-8"), "use": "sig",
     "alg": "HS256"})


def query_string_compare(query_str1, query_str2):
    return parse_qs(query_str1) == parse_qs(query_str2)


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_openidschema():
    inp = '{"middle_name":null, "updated_at":"20170328081544", "sub":"abc"}'
    ois = OpenIDSchema().from_json(inp)
    assert ois.verify() is False


@pytest.mark.parametrize("json_param", [
    '{"middle_name":"fo", "updated_at":"20170328081544Z", "sub":"abc"}',
    '{"middle_name":true, "updated_at":"20170328081544", "sub":"abc"}',
    '{"middle_name":"fo", "updated_at":false, "sub":"abc"}',
    '{"middle_name":"fo", "updated_at":"20170328081544Z", "sub":true}'
])
def test_openidschema_from_json(json_param):
    with pytest.raises(ValueError):
        OpenIDSchema().from_json(json_param)


@pytest.mark.parametrize("json_param", [
    '{"email_verified":false, "email":"foo@example.com", "sub":"abc"}',
    '{"email_verified":true, "email":"foo@example.com", "sub":"abc"}',
    '{"phone_number_verified":false, "phone_number":"+1 555 200000", '
    '"sub":"abc"}',
    '{"phone_number_verified":true, "phone_number":"+1 555 20000", '
    '"sub":"abc"}',
])
def test_claim_booleans(json_param):
    assert OpenIDSchema().from_json(json_param)


@pytest.mark.parametrize("json_param", [
    '{"email_verified":"Not", "email":"foo@example.com", "sub":"abc"}',
    '{"email_verified":"Sure", "email":"foo@example.com", "sub":"abc"}',
    '{"phone_number_verified":"Not", "phone_number":"+1 555 200000", '
    '"sub":"abc"}',
    '{"phone_number_verified":"Sure", "phone_number":"+1 555 20000", '
    '"sub":"abc"}',
])
def test_claim_not_booleans(json_param):
    with pytest.raises(ValueError):
        OpenIDSchema().from_json(json_param)


def test_claims_deser():
    _dic = {
        "userinfo": {
            "given_name": {"essential": True},
            "nickname": None,
            "email": {"essential": True},
            "email_verified": {"essential": True},
            "picture": None,
            "http://example.info/claims/groups": None
        },
        "id_token": {
            "auth_time": {"essential": True},
            "acr": {"values": ["urn:mace:incommon:iap:silver"]}
        }
    }

    claims = claims_deser(json.dumps(_dic), sformat="json")
    assert _eq(claims.keys(), ["userinfo", "id_token"])


def test_claims_deser_dict():
    pre = Claims(name={"essential": True}, nickname=None,
                 email={"essential": True},
                 email_verified={"essential": True}, picture=None)

    claims = claims_deser(pre.to_json(), sformat="json")
    assert _eq(claims.keys(), ['name', 'nickname', 'email', 'email_verified',
                               'picture'])

    claims = claims_deser(pre.to_dict(), sformat="dict")
    assert _eq(claims.keys(), ['name', 'nickname', 'email', 'email_verified',
                               'picture'])


def test_address_deser():
    pre = AddressClaim(street_address="Kasamark 114", locality="Umea",
                       country="Sweden")

    adc = address_deser(pre.to_json(), sformat="json")
    assert _eq(adc.keys(), ['street_address', 'locality', 'country'])

    adc = address_deser(pre.to_dict(), sformat="json")
    assert _eq(adc.keys(), ['street_address', 'locality', 'country'])


def test_msg_ser_json():
    pre = AddressClaim(street_address="Kasamark 114", locality="Umea",
                       country="Sweden")

    ser = msg_ser_json(pre, "json")

    adc = address_deser(ser, "json")
    assert _eq(adc.keys(), ['street_address', 'locality', 'country'])


def test_msg_ser_json_from_dict():
    ser = msg_ser_json({'street_address': "Kasamark 114", 'locality': "Umea",
                        'country': "Sweden"}, "json")

    adc = address_deser(ser, "json")
    assert _eq(adc.keys(), ['street_address', 'locality', 'country'])


def test_msg_ser_json_to_dict():
    pre = AddressClaim(street_address="Kasamark 114", locality="Umea",
                       country="Sweden")

    ser = msg_ser_json(pre, "dict")

    adc = address_deser(ser, "dict")
    assert _eq(adc.keys(), ['street_address', 'locality', 'country'])


def test_msg_ser_urlencoded():
    pre = AddressClaim(street_address="Kasamark 114", locality="Umea",
                       country="Sweden")

    ser = msg_ser(pre.to_dict(), "urlencoded")

    adc = address_deser(ser, "urlencoded")
    assert _eq(adc.keys(), ['street_address', 'locality', 'country'])


def test_msg_ser_dict():
    pre = AddressClaim(street_address="Kasamark 114", locality="Umea",
                       country="Sweden")

    ser = msg_ser(pre.to_dict(), "dict")

    adc = address_deser(ser, "dict")
    assert _eq(adc.keys(), ['street_address', 'locality', 'country'])


def test_msg_ser_from_dict():
    pre = {"street_address": "Kasamark 114", "locality": "Umea",
           "country": "Sweden"}

    ser = msg_ser(pre, "dict")

    adc = address_deser(ser, "dict")
    assert _eq(adc.keys(), ['street_address', 'locality', 'country'])


def test_claims_ser_json():
    claims = Claims(name={"essential": True}, nickname=None,
                    email={"essential": True},
                    email_verified={"essential": True}, picture=None)
    claims = claims_deser(claims_ser(claims, "json"), sformat="json")
    assert _eq(claims.keys(), ['name', 'nickname', 'email', 'email_verified',
                               'picture'])


def test_claims_ser_from_dict_to_json():
    claims = claims_ser({
        "name": {"essential": True},
        "nickname": None,
        "email": {"essential": True},
        "email_verified": {"essential": True},
        "picture": None
    }, sformat="json")
    cl = Claims().from_json(claims)
    assert _eq(cl.keys(), ['name', 'nickname', 'email', 'email_verified',
                           'picture'])


def test_claims_ser_from_dict_to_urlencoded():
    claims = claims_ser({
        "name": {"essential": True},
        "nickname": None,
        "email": {"essential": True},
        "email_verified": {"essential": True},
        "picture": None
    }, sformat="urlencoded")
    cl = Claims().from_urlencoded(claims)
    assert _eq(cl.keys(), ['name', 'nickname', 'email', 'email_verified',
                           'picture'])


def test_discovery_request():
    request = {'rel': "http://openid.net/specs/connect/1.0/issuer",
               'resource': 'diana@localhost'}

    req = DiscoveryRequest().from_json(json.dumps(request))
    assert set(req.keys()) == {'rel', 'resource'}


def test_discovery_response():
    link = Link(href='https://example.com/op',
                rel="http://openid.net/specs/connect/1.0/issuer")

    resp = JRD(subject='diana@localhost', links=[link])

    assert set(resp.keys()) == {'subject', 'links'}


class TestProviderConfigurationResponse(object):
    def test_deserialize(self):
        resp = {
            "authorization_endpoint":
                "https://server.example.com/connect/authorize",
            "issuer": "https://server.example.com",
            "token_endpoint": "https://server.example.com/connect/token",
            "token_endpoint_auth_methods_supported": ["client_secret_basic",
                                                      "private_key_jwt"],
            "userinfo_endpoint": "https://server.example.com/connect/user",
            "check_id_endpoint": "https://server.example.com/connect/check_id",
            "refresh_session_endpoint":
                "https://server.example.com/connect/refresh_session",
            "end_session_endpoint":
                "https://server.example.com/connect/end_session",
            "jwk_url": "https://server.example.com/jwk.json",
            "registration_endpoint":
                "https://server.example.com/connect/register",
            "scopes_supported": ["openid", "profile", "email", "address",
                                 "phone"],
            "response_types_supported": ["code", "code id_token",
                                         "token id_token"],
            "acrs_supported": ["1", "2",
                               "http://id.incommon.org/assurance/bronze"],
            "user_id_types_supported": ["public", "pairwise"],
            "userinfo_algs_supported": ["HS256", "RS256", "A128CBC", "A128KW",
                                        "RSA1_5"],
            "id_token_algs_supported": ["HS256", "RS256", "A128CBC", "A128KW",
                                        "RSA1_5"],
            "request_object_algs_supported": ["HS256", "RS256", "A128CBC",
                                              "A128KW",
                                              "RSA1_5"]
        }

        pcr = ProviderConfigurationResponse().deserialize(json.dumps(resp),
                                                          "json")

        with pytest.raises(MissingRequiredAttribute):
            assert pcr.verify()

        assert _eq(pcr["user_id_types_supported"], ["public", "pairwise"])
        assert _eq(pcr["acrs_supported"],
                   ["1", "2", "http://id.incommon.org/assurance/bronze"])

    def test_example_response(self):
        resp = {
            "version": "3.0",
            "issuer": "https://server.example.com",
            "authorization_endpoint":
                "https://server.example.com/connect/authorize",
            "token_endpoint": "https://server.example.com/connect/token",
            "token_endpoint_auth_methods_supported": ["client_secret_basic",
                                                      "private_key_jwt"],
            "token_endpoint_alg_values_supported": ["RS256", "ES256"],
            "userinfo_endpoint": "https://server.example.com/connect/userinfo",
            "check_session_iframe":
                "https://server.example.com/connect/check_session",
            "end_session_endpoint":
                "https://server.example.com/connect/end_session",
            "jwks_uri": "https://server.example.com/jwks.json",
            "registration_endpoint":
                "https://server.example.com/connect/register",
            "scopes_supported": ["openid", "profile", "email", "address",
                                 "phone", "offline_access"],
            "response_types_supported": ["code", "code id_token", "id_token",
                                         "token id_token"],
            "acr_values_supported": ["urn:mace:incommon:iap:silver",
                                     "urn:mace:incommon:iap:bronze"],
            "subject_types_supported": ["public", "pairwise"],
            "userinfo_signing_alg_values_supported": ["RS256", "ES256",
                                                      "HS256"],
            "userinfo_encryption_alg_values_supported": ["RSA1_5", "A128KW"],
            "userinfo_encryption_enc_values_supported": ["A128CBC+HS256",
                                                         "A128GCM"],
            "id_token_signing_alg_values_supported": ["RS256", "ES256",
                                                      "HS256"],
            "id_token_encryption_alg_values_supported": ["RSA1_5", "A128KW"],
            "id_token_encryption_enc_values_supported": ["A128CBC+HS256",
                                                         "A128GCM"],
            "request_object_signing_alg_values_supported": ["none", "RS256",
                                                            "ES256"],
            "display_values_supported": ["page", "popup"],
            "claim_types_supported": ["normal", "distributed"],
            "claims_supported": ["sub", "iss", "auth_time", "acr", "name",
                                 "given_name", "family_name", "nickname",
                                 "profile",
                                 "picture", "website", "email",
                                 "email_verified",
                                 "locale", "zoneinfo",
                                 "http://example.info/claims/groups"],
            "claims_parameter_supported": True,
            "service_documentation":
                "http://server.example.com/connect/service_documentation.html",
            "ui_locales_supported": ["en-US", "en-GB", "en-CA", "fr-FR",
                                     "fr-CA"]
        }

        pcr = ProviderConfigurationResponse().deserialize(json.dumps(resp),
                                                          "json")
        assert pcr.verify()
        rk = list(resp.keys())
        # parameters with default value if missing
        rk.extend(["grant_types_supported", "request_parameter_supported",
                   "request_uri_parameter_supported",
                   "require_request_uri_registration"])
        assert sorted(rk) == sorted(list(pcr.keys()))

    @pytest.mark.parametrize("required_param", [
        "issuer",
        "authorization_endpoint",
        "jwks_uri",
        "response_types_supported",
        "subject_types_supported",
        "id_token_signing_alg_values_supported"
    ])
    def test_required_parameters(self, required_param):
        provider_config = {
            "issuer": "https://server.example.com",
            "authorization_endpoint":
                "https://server.example.com/connect/authorize",
            "jwks_uri": "https://server.example.com/jwks.json",
            "response_types_supported": ["code", "code id_token", "id_token",
                                         "token id_token"],
            "subject_types_supported": ["public", "pairwise"],
            "id_token_signing_alg_values_supported": ["RS256", "ES256",
                                                      "HS256"],
        }

        del provider_config[required_param]
        with pytest.raises(MissingRequiredAttribute):
            ProviderConfigurationResponse(**provider_config).verify()

    def test_token_endpoint_is_not_required_for_implicit_flow_only(self):
        provider_config = {
            "issuer": "https://server.example.com",
            "authorization_endpoint":
                "https://server.example.com/connect/authorize",
            "jwks_uri": "https://server.example.com/jwks.json",
            "response_types_supported": ["id_token", "token id_token"],
            "subject_types_supported": ["public", "pairwise"],
            "id_token_signing_alg_values_supported": ["RS256", "ES256",
                                                      "HS256"],
        }

        # should not raise an exception
        assert ProviderConfigurationResponse(**provider_config).verify()

    def test_token_endpoint_is_required_for_other_than_implicit_flow_only(self):
        provider_config = {
            "issuer": "https://server.example.com",
            "authorization_endpoint":
                "https://server.example.com/connect/authorize",
            "jwks_uri": "https://server.example.com/jwks.json",
            "response_types_supported": ["code", "id_token"],
            "subject_types_supported": ["public", "pairwise"],
            "id_token_signing_alg_values_supported": ["RS256", "ES256",
                                                      "HS256"],
        }

        with pytest.raises(MissingRequiredAttribute):
            ProviderConfigurationResponse(**provider_config).verify()


class TestRegistrationRequest(object):
    def test_deserialize(self):
        msg = {
            "application_type": "web",
            "redirect_uris": ["https://client.example.org/callback",
                              "https://client.example.org/callback2"],
            "client_name": "My Example",
            "client_name#ja-Jpan-JP": "クライアント名",
            "logo_uri": "https://client.example.org/logo.png",
            "subject_type": "pairwise",
            "sector_identifier_uri":
                "https://other.example.net/file_of_redirect_uris.json",
            "token_endpoint_auth_method": "client_secret_basic",
            "jwks_uri": "https://client.example.org/my_public_keys.jwks",
            "userinfo_encrypted_response_alg": "RSA1_5",
            "userinfo_encrypted_response_enc": "A128CBC+HS256",
            "contacts": ["ve7jtb@example.org", "mary@example.org"],
            "request_uris": [
                "https://client.example.org/rf.txt"
                "#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"]
        }

        reg = RegistrationRequest().deserialize(json.dumps(msg), "json")
        assert reg.verify()

        assert _eq(list(msg.keys()) + ['response_types'], reg.keys())

    def test_registration_request(self):
        req = RegistrationRequest(operation="register", default_max_age=10,
                                  require_auth_time=True, default_acr="foo",
                                  application_type="web",
                                  redirect_uris=[
                                      "https://example.com/authz_cb"])
        assert req.verify()
        js = req.to_json()
        js_obj = json.loads(js)
        expected_js_obj = {"redirect_uris": ["https://example.com/authz_cb"],
                           "application_type": "web", "default_acr": "foo",
                           "require_auth_time": True, "operation": "register",
                           "default_max_age": 10, "response_types": ["code"]}
        assert js_obj == expected_js_obj

        flattened_list_dict = {k: v[0] if isinstance(v, list) else v for k, v in
                               expected_js_obj.items()}
        assert query_string_compare(req.to_urlencoded(),
                                    urlencode(flattened_list_dict))

    @pytest.mark.parametrize("enc_param", [
        "request_object_encryption_enc",
        "id_token_encrypted_response_enc",
        "userinfo_encrypted_response_enc",
    ])
    def test_registration_request_with_coupled_encryption_params(self,
                                                                 enc_param):
        registration_params = {
            "redirect_uris": ["https://example.com/authz_cb"],
            enc_param: "RS25asdasd6"}
        registration_req = RegistrationRequest(**registration_params)
        with pytest.raises(MissingRequiredAttribute):
            registration_req.verify()


class TestRegistrationResponse(object):
    def test_deserialize(self):
        msg = {
            "client_id": "s6BhdRkqt3",
            "client_secret": "ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk",
            "client_secret_expires_at": 1577858400,
            "registration_access_token": "this.is.an.access.token.value.ffx83",
            "registration_client_uri":
                "https://server.example.com/connect/register?client_id"
                "=s6BhdRkqt3",
            "token_endpoint_auth_method": "client_secret_basic",
            "application_type": "web",
            "redirect_uris": ["https://client.example.org/callback",
                              "https://client.example.org/callback2"],
            "client_name": "My Example",
            "client_name#ja-Jpan-JP": "クライアント名",
            "logo_uri": "https://client.example.org/logo.png",
            "subject_type": "pairwise",
            "sector_identifier_uri":
                "https://other.example.net/file_of_redirect_uris.json",
            "jwks_uri": "https://client.example.org/my_public_keys.jwks",
            "userinfo_encrypted_response_alg": "RSA1_5",
            "userinfo_encrypted_response_enc": "A128CBC+HS256",
            "contacts": ["ve7jtb@example.org", "mary@example.org"],
            "request_uris": [
                "https://client.example.org/rf.txt"
                "#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"]
        }

        resp = RegistrationResponse().deserialize(json.dumps(msg), "json")
        assert resp.verify()
        assert _eq(msg.keys(), resp.keys())


class TestAuthorizationRequest(object):
    def test_deserialize(self):
        query = "response_type=token%20id_token&client_id=0acf77d4-b486-4c99" \
                "-bd76-074ed6a64ddf&redirect_uri=https%3A%2F%2Fclient.example" \
                ".com%2Fcb&scope=openid%20profile&state=af0ifjsldkj&nonce=n" \
                "-0S6_WzA2Mj"

        req = AuthorizationRequest().deserialize(query, "urlencoded")

        assert _eq(req.keys(),
                   ['nonce', 'state', 'redirect_uri', 'response_type',
                    'client_id', 'scope'])

        assert req["response_type"] == ["token", "id_token"]
        assert req["scope"] == ["openid", "profile"]

    def test_verify_no_scopes(self):
        args = {
            "client_id": "foobar",
            "redirect_uri": "http://foobar.example.com/oaclient",
            "response_type": "code",
        }
        ar = AuthorizationRequest(**args)
        with pytest.raises(MissingRequiredAttribute):
            ar.verify()

    def test_claims(self):
        args = {
            "client_id": "foobar",
            "redirect_uri": "http://foobar.example.com/oaclient",
            "response_type": "code",
            'scope': 'openid',
            'claims': {
                "userinfo":
                    {
                        "given_name": {"essential": True},
                        "nickname": None,
                        "email": {"essential": True},
                        "email_verified": {"essential": True},
                        "picture": None,
                        "http://example.info/claims/groups": None
                    },
                "id_token":
                    {
                        "auth_time": {"essential": True},
                        "acr": {"values": ["urn:mace:incommon:iap:silver"]}
                    }
            }
        }
        ar = AuthorizationRequest(**args)
        assert ar.verify()

        ar_url = ar.to_urlencoded()
        ar2 = AuthorizationRequest().from_urlencoded(ar_url)
        assert ar2.verify()

        ar_json = ar.to_json()
        ar3 = AuthorizationRequest().from_json(ar_json)
        assert ar3.verify()


class TestAccessTokenResponse(object):
    def test_faulty_idtoken(self):
        idval = {'nonce': 'KUEYfRM2VzKDaaKD', 'sub': 'EndUserSubject',
                 'iss': 'https://alpha.cloud.nds.rub.de', 'aud': 'TestClient'}
        idts = IdToken(**idval)
        keyjar = KeyJar()
        keyjar.add_symmetric('', "TestPassword")
        _signed_jwt = idts.to_jwt(key=keyjar.get_signing_key('oct'),
                                  algorithm="HS256", lifetime=300)
        # Mess with the signed id_token
        p = _signed_jwt.split(".")
        p[2] = "aaa"
        _faulty_signed_jwt = ".".join(p)

        _info = {"access_token": "accessTok", "id_token": _faulty_signed_jwt,
                 "token_type": "Bearer", "expires_in": 3600}

        at = AccessTokenResponse(**_info)
        with pytest.raises(BadSignature):
            at.verify(keyjar=keyjar)

    def test_wrong_alg(self):
        idval = {'nonce': 'KUEYfRM2VzKDaaKD', 'sub': 'EndUserSubject',
                 'iss': 'https://alpha.cloud.nds.rub.de', 'aud': 'TestClient'}
        idts = IdToken(**idval)
        keyjar = KeyJar()
        keyjar.add_symmetric('', "TestPassword")
        _signed_jwt = idts.to_jwt(key=keyjar.get_signing_key('oct'),
                                  algorithm="HS256", lifetime=300)

        _info = {"access_token": "accessTok", "id_token": _signed_jwt,
                 "token_type": "Bearer", "expires_in": 3600}

        at = AccessTokenResponse(**_info)
        with pytest.raises(WrongSigningAlgorithm):
            at.verify(keyjar=keyjar, algs={"sign": "HS512"})


def test_at_hash():
    lifetime = 3600
    _token = {'access_token': 'accessTok'}
    idval = {'nonce': 'KUEYfRM2VzKDaaKD', 'sub': 'EndUserSubject',
             'iss': 'https://alpha.cloud.nds.rub.de', 'aud': 'TestClient'}
    idval.update(_token)

    idts = IdToken(**idval)
    keyjar = KeyJar()
    keyjar.add_symmetric('', "TestPassword")
    _signed_jwt = idts.to_jwt(key=keyjar.get_signing_key('oct'),
                              algorithm="HS256", lifetime=lifetime)

    _info = {"id_token": _signed_jwt, "token_type": "Bearer",
             "expires_in": lifetime}
    _info.update(_token)

    at = AuthorizationResponse(**_info)
    assert at.verify(keyjar=keyjar, algs={"sign": "HS256"})
    assert 'at_hash' in at['verified_id_token']


def test_c_hash():
    lifetime = 3600
    _token = {'code': 'grant'}

    idval = {'nonce': 'KUEYfRM2VzKDaaKD', 'sub': 'EndUserSubject',
             'iss': 'https://alpha.cloud.nds.rub.de', 'aud': 'TestClient'}
    idval.update(_token)

    idts = IdToken(**idval)
    keyjar = KeyJar()
    keyjar.add_symmetric('', "TestPassword")

    _signed_jwt = idts.to_jwt(key=keyjar.get_signing_key('oct'),
                              algorithm="HS256", lifetime=lifetime)

    _info = {"id_token": _signed_jwt, "token_type": "Bearer",
             "expires_in": lifetime}
    _info.update(_token)

    at = AuthorizationResponse(**_info)
    r = at.verify(keyjar=keyjar, algs={"sign": "HS256"})
    assert 'c_hash' in at['verified_id_token']


def test_missing_c_hash():
    lifetime = 3600
    _token = {'code': 'grant'}

    idval = {'nonce': 'KUEYfRM2VzKDaaKD', 'sub': 'EndUserSubject',
             'iss': 'https://alpha.cloud.nds.rub.de', 'aud': 'TestClient'}
    # idval.update(_token)

    idts = IdToken(**idval)
    keyjar = KeyJar()
    keyjar.add_symmetric('', "TestPassword")

    _signed_jwt = idts.to_jwt(key=keyjar.get_signing_key('oct'),
                              algorithm="HS256", lifetime=lifetime)

    _info = {"id_token": _signed_jwt, "token_type": "Bearer",
             "expires_in": lifetime}
    _info.update(_token)

    at = AuthorizationResponse(**_info)
    with pytest.raises(MissingRequiredAttribute):
        at.verify(keyjar=keyjar, algs={"sign": "HS256"})


def test_id_token():
    _now = time_util.utc_time_sans_frac()

    idt = IdToken(**{
        "sub": "553df2bcf909104751cfd8b2",
        "aud": [
            "5542958437706128204e0000",
            "554295ce3770612820620000"
        ],
        "auth_time": 1441364872,
        "azp": "554295ce3770612820620000",
        "at_hash": "L4Ign7TCAD_EppRbHAuCyw",
        "iat": _now,
        "exp": _now + 3600,
        "iss": "https://sso.qa.7pass.ctf.prosiebensat1.com"
    })

    idt.verify()


class TestAccessTokenRequest(object):
    def test_example(self):
        _txt = 'grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA' \
               '&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb'
        atr = AccessTokenRequest().from_urlencoded(_txt)
        assert atr.verify()


class TestAuthnToken(object):
    def test_example(self):
        at = AuthnToken(
            iss='https://example.com',
            sub='https://example,org',
            aud=['https://example.org/token'],  # Array of strings or string
            jti='abcdefghijkl',
            exp=utc_time_sans_frac() + 3600,
        )
        assert at.verify()


class TestAuthorizationErrorResponse(object):
    def test_allowed_err(self):
        aer = AuthorizationErrorResponse(error='interaction_required')
        assert aer.verify()

    def test_not_allowed_err(self):
        aer = AuthorizationErrorResponse(error='other_error')
        with pytest.raises(NotAllowedValue):
            assert aer.verify()


class TestEndSessionResponse(object):
    def test_example(self):
        esr = EndSessionResponse()
        pass


class TestEndSessionRequest(object):
    def test_example(self):
        _symkey = KC_SYM_S.get(alg2keytype("HS256"))
        esreq = EndSessionRequest(
            id_token_hint=IDTOKEN.to_jwt(key=_symkey, algorithm="HS256",
                                         lifetime=300),
            redirect_url="http://example.org/jqauthz",
            state="state0")

        request = EndSessionRequest().from_urlencoded(esreq.to_urlencoded())
        keyjar=KeyJar()
        for _key in _symkey:
            keyjar.add_symmetric('', _key.key)
        request.verify(keyjar=keyjar)
        assert isinstance(request, EndSessionRequest)
        assert _eq(request.keys(), ['id_token_hint', 'redirect_url', 'state'])
        assert request["state"] == "state0"
        assert request["id_token_hint"]["aud"] == ["client_1"]


class TestCheckSessionRequest(object):
    def test_example(self):
        _symkey = KC_SYM_S.get(alg2keytype("HS256"))
        csr = CheckSessionRequest(
            id_token=IDTOKEN.to_jwt(key=_symkey, algorithm="HS256",
                                    lifetime=300))
        keyjar = KeyJar()
        keyjar.add_kb('', KC_SYM_S)
        assert csr.verify(keyjar=keyjar)


class TestClaimsRequest(object):
    def test_example(self):
        claims = {
            "name": {"essential": True},
            "nickname": None,
            "email": {"essential": True},
            "verified": {"essential": True},
            "picture": None
        }

        cr = ClaimsRequest(userinfo=Claims(**claims),
                           id_token=Claims(auth_time=None,
                                           acr={"values": ["2"]}))
        cr.verify()
        _url = cr.to_urlencoded()
        cr1 = ClaimsRequest().from_urlencoded(_url)
        cr1.verify()

        _js = cr.to_json()
        cr1 = ClaimsRequest().from_json(_js)
        cr1.verify()


@pytest.mark.parametrize("bdate", [
    "1971-11-23", "0000-11-23", "1971"
])
def test_birthdate(bdate):
    uinfo = OpenIDSchema(birthdate=bdate, sub='jarvis')
    uinfo.verify()


def test_factory():
    dr = factory('DiscoveryRequest', resource='local@domain',
                 rel="http://openid.net/specs/connect/1.0/issuer")
    assert isinstance(dr, DiscoveryRequest)
    assert set(dr.keys()) == {'resource', 'rel'}


def test_factory_chain():
    dr = factory('ResponseMessage', error='some_error')
    assert isinstance(dr, ResponseMessage)
    assert list(dr.keys()) == ['error']


def test_scope2claims():
    assert scope2claims(['openid']) == {'sub': None}
    assert set(scope2claims(['profile']).keys()) == {
        "name", "given_name", "family_name", "middle_name", "nickname",
        "profile", "picture", "website", "gender", "birthdate", "zoneinfo",
        "locale", "updated_at", "preferred_username"}
    assert set(scope2claims(['email']).keys()) == {"email", "email_verified"}
    assert set(scope2claims(['address']).keys()) == {'address'}
    assert set(scope2claims(['phone']).keys()) == {"phone_number",
                                                   "phone_number_verified"}
    assert scope2claims(['offline_access']) == {}

    assert scope2claims(['openid', 'email', 'phone']) == {
        'sub': None, "email": None, "email_verified": None,
        "phone_number": None, "phone_number_verified": None
    }

# class ClaimsRequest(Message):
# class ClientRegistrationErrorResponse(oauth2.ErrorResponse):
# class DiscoveryRequest(Message):
# class DiscoveryResponse(Message):
# class IdTMessage(AuthorizationResponse):
# class IdToken(OpenIDSchema):
# class JsonWebToken(Message):
# class OpenIDRequest(AuthorizationRequest):
# class OpenIDSchema(Message):
# class ProviderConfigurationResponse(Message):
# class RefreshAccessTokenRequest(oauth2.RefreshAccessTokenRequest):
# class RefreshSessionRequest(Message):
# class RefreshSessionResponse(Message):
# class RegistrationRequest(Message):
# class RegistrationResponse(Message):
# class ResourceRequest(Message):
# class TokenErrorResponse(oauth2.TokenErrorResponse):
# class UserInfoErrorResponse(oauth2.ErrorResponse):
# class UserInfoRequest(Message):
