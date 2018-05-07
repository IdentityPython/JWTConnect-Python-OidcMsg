# encoding: utf-8
import uuid

from urllib.parse import urlencode
from urllib.parse import urlparse

import inspect
import json
import logging
import six
import sys
import time

from cryptojwt import as_unicode
from cryptojwt import jws

from oidcmsg import oauth2
from oidcmsg import time_util
from oidcmsg.exception import InvalidRequest
from oidcmsg.exception import IssuerMismatch
from oidcmsg.exception import MessageException
from oidcmsg.exception import MissingRequiredAttribute
from oidcmsg.exception import MissingRequiredValue
from oidcmsg.exception import NotAllowedValue
from oidcmsg.exception import NotForMe
from oidcmsg.exception import OidcMsgError
from oidcmsg.exception import SchemeError
from oidcmsg.exception import VerificationError
from oidcmsg.message import Message
from oidcmsg.message import msg_ser
from oidcmsg.message import OPTIONAL_LIST_OF_SP_SEP_STRINGS
from oidcmsg.message import OPTIONAL_LIST_OF_STRINGS
from oidcmsg.message import OPTIONAL_MESSAGE
from oidcmsg.message import REQUIRED_LIST_OF_SP_SEP_STRINGS
from oidcmsg.message import REQUIRED_LIST_OF_STRINGS
from oidcmsg.message import SINGLE_OPTIONAL_INT
from oidcmsg.message import SINGLE_OPTIONAL_JSON
from oidcmsg.message import SINGLE_OPTIONAL_STRING
from oidcmsg.message import SINGLE_REQUIRED_STRING
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.time_util import utc_time_sans_frac

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)

NONCE_STORAGE_TIME = 4 * 3600


class AtHashError(VerificationError):
    pass


class CHashError(VerificationError):
    pass


class EXPError(VerificationError):
    pass


class IATError(VerificationError):
    pass


def json_ser(val, sformat=None, lev=0):
    return json.dumps(val)


def json_deser(val, sformat=None, lev=0):
    return json.loads(val)


# value type, required, serializer, deserializer, null value allowed
SINGLE_OPTIONAL_BOOLEAN = (bool, False, None, None, False)
SINGLE_OPTIONAL_JSON_WN = (dict, False, json_ser, json_deser, True)
# SINGLE_OPTIONAL_JSON_CONV = (dict, False, json_conv, json_rest, True)
SINGLE_REQUIRED_INT = (int, True, None, None, False)


def idtoken_deser(val, sformat="urlencoded"):
    # id_token are always serialized as a JWT
    return IdToken().deserialize(val, "jwt")


def address_deser(val, sformat="urlencoded"):
    if sformat in ["dict", "json"]:
        if not isinstance(val, six.string_types):
            val = json.dumps(val)
            sformat = "json"
        elif sformat == "dict":
            sformat = "json"
    return AddressClaim().deserialize(val, sformat)


def claims_deser(val, sformat="urlencoded"):
    if sformat in ["dict", "json"]:
        if not isinstance(val, six.string_types):
            val = json.dumps(val)
            sformat = "json"
    return Claims().deserialize(val, sformat)


def msg_ser_json(inst, sformat="json", lev=0):
    # sformat = "json" always except when dict
    if lev:
        sformat = "dict"

    if sformat == "dict":
        if isinstance(inst, Message):
            res = inst.serialize(sformat, lev)
        elif isinstance(inst, dict):
            res = inst
        else:
            raise MessageException("Wrong type: %s" % type(inst))
    else:
        sformat = "json"
        if isinstance(inst, dict):
            res = json.dumps(inst)
        elif isinstance(inst, Message):
            res = inst.serialize(sformat, lev)
        else:
            res = inst

    return res


def msg_list_ser(insts, sformat, lev=0):
    return [msg_ser(inst, sformat, lev) for inst in insts]


def claims_ser(val, sformat="urlencoded", lev=0):
    # everything in c_extension
    if isinstance(val, six.string_types):
        item = val
    elif isinstance(val, list):
        item = val[0]
    else:
        item = val

    if isinstance(item, Message):
        return item.serialize(method=sformat, lev=lev + 1)

    if sformat == "urlencoded":
        res = urlencode(item)
    elif sformat == "json":
        if lev:
            res = item
        else:
            res = json.dumps(item)
    elif sformat == "dict":
        if isinstance(item, dict):
            res = item
        else:
            raise MessageException("Wrong type: %s" % type(item))
    else:
        raise OidcMsgError("Unknown sformat: %s" % sformat, val)

    return res


def registration_request_deser(val, sformat="urlencoded"):
    if sformat in ["dict", "json"]:
        if not isinstance(val, six.string_types):
            val = json.dumps(val)
            sformat = "json"
    return RegistrationRequest().deserialize(val, sformat)


def claims_request_deser(val, sformat="json"):
    # never 'urlencoded'
    if sformat == "urlencoded":
        sformat = "json"
    if sformat in ["dict", "json"]:
        if not isinstance(val, six.string_types):
            val = json.dumps(val)
            sformat = "json"
    return ClaimsRequest().deserialize(val, sformat)


def dict_deser(val, sformat="json"):
    # never 'urlencoded'
    if sformat == "urlencoded":
        sformat = "json"
    if sformat in ["dict", "json"]:
        if not isinstance(val, six.string_types):
            val = json.dumps(val)
        elif isinstance(val, dict):
            return val
    else:
        raise ValueError('sformat can not be "{}"'.format(sformat))


OPTIONAL_ADDRESS = (Message, False, msg_ser, address_deser, False)
OPTIONAL_LOGICAL = (bool, False, None, None, False)
OPTIONAL_MULTIPLE_Claims = (Message, False, claims_ser, claims_deser, False)
# SINGLE_OPTIONAL_USERINFO_CLAIM = (Message, False, msg_ser, userinfo_deser)
# SINGLE_OPTIONAL_ID_TOKEN_CLAIM = (Message, False, msg_ser, idtokenclaim_deser)

SINGLE_OPTIONAL_IDTOKEN = (Message, False, msg_ser, None, False)
SINGLE_REQUIRED_IDTOKEN = (Message, True, msg_ser, None, False)

SINGLE_OPTIONAL_REGISTRATION_REQUEST = (Message, False, msg_ser,
                                        registration_request_deser, False)
SINGLE_OPTIONAL_CLAIMSREQ = (Message, False, msg_ser_json, claims_request_deser,
                             False)

SINGLE_OPTIONAL_DICT = (dict, False, msg_ser_json, dict_deser, False)

# ----------------------------------------------------------------------------


SCOPE_CHARSET = []
for char in ['\x21', ('\x23', '\x5b'), ('\x5d', '\x7E')]:
    if isinstance(char, tuple):
        c = char[0]
        while c <= char[1]:
            SCOPE_CHARSET.append(c)
            c = chr(ord(c) + 1)
    else:
        SCOPE_CHARSET.append(set)


def check_char_set(string, allowed):
    for c in string:
        if c not in allowed:
            raise NotAllowedValue("'%c' not in the allowed character set" % c)


# -----------------------------------------------------------------------------

ID_TOKEN_VERIFY_ARGS = ['keyjar','verify', 'encalg', 'encenc', 'sigalg',
                        'issuer', 'allow_missing_kid', 'no_kid_issuer',
                        'trusting', 'skew', 'nonce_storage_time', 'client_id']

class RefreshAccessTokenRequest(oauth2.RefreshAccessTokenRequest):
    pass


class TokenErrorResponse(oauth2.TokenErrorResponse):
    pass


class AccessTokenResponse(oauth2.AccessTokenResponse):
    c_param = oauth2.AccessTokenResponse.c_param.copy()
    c_param.update({"id_token": SINGLE_OPTIONAL_STRING})

    def verify(self, **kwargs):
        super(AccessTokenResponse, self).verify(**kwargs)
        if "id_token" in self:
            # Try to decode the JWT, checks the signature
            args = {}
            for arg in ID_TOKEN_VERIFY_ARGS:
                try:
                    args[arg] = kwargs[arg]
                except KeyError:
                    pass
            idt = IdToken().from_jwt(str(self["id_token"]), **args)
            if not idt.verify(**kwargs):
                return False

            self["__verified_id_token"] = idt
            logger.info('Verified ID Token: {}'.format(idt.to_dict()))

        return True


class UserInfoRequest(Message):
    c_param = {
        "access_token": SINGLE_OPTIONAL_STRING,
    }


class AuthorizationResponse(oauth2.AuthorizationResponse,
                            oauth2.AccessTokenResponse):
    c_param = oauth2.AuthorizationResponse.c_param.copy()
    c_param.update(oauth2.AccessTokenResponse.c_param)
    c_param.update({
        "code": SINGLE_OPTIONAL_STRING,
        # "nonce": SINGLE_OPTIONAL_STRING,
        "access_token": SINGLE_OPTIONAL_STRING,
        "token_type": SINGLE_OPTIONAL_STRING,
        "id_token": SINGLE_OPTIONAL_IDTOKEN
    })

    def verify(self, **kwargs):
        super(AuthorizationResponse, self).verify(**kwargs)

        if "aud" in self:
            if "client_id" in kwargs:
                # check that it's for me
                if kwargs["client_id"] not in self["aud"]:
                    return False

        if "id_token" in self:
            # Try to decode the JWT, checks the signature
            args = {}
            for arg in ID_TOKEN_VERIFY_ARGS:
                try:
                    args[arg] = kwargs[arg]
                except KeyError:
                    pass
            idt = IdToken().from_jwt(str(self["id_token"]), **args)
            if not idt.verify(**kwargs):
                raise VerificationError("Could not verify id_token", idt)

            _alg = idt.jws_header["alg"]
            # What if _alg == 'none'

            hfunc = "HS" + _alg[-3:]

            if "access_token" in self:
                if "at_hash" not in idt:
                    raise MissingRequiredAttribute("Missing at_hash property",
                                                   idt)
                if idt["at_hash"] != jws.left_hash(self["access_token"],
                                                   hfunc):
                    raise AtHashError(
                        "Failed to verify access_token hash", idt)

            if "code" in self:
                if "c_hash" not in idt:
                    raise MissingRequiredAttribute("Missing c_hash property",
                                                   idt)
                if idt["c_hash"] != jws.left_hash(self["code"], hfunc):
                    raise CHashError("Failed to verify code hash", idt)

            self["__verified_id_token"] = idt
        return True


class AuthorizationErrorResponse(oauth2.AuthorizationErrorResponse):
    c_allowed_values = oauth2.AuthorizationErrorResponse.c_allowed_values \
        .copy()
    c_allowed_values["error"].extend(["interaction_required",
                                      "login_required",
                                      "session_selection_required",
                                      "consent_required",
                                      "invalid_request_uri",
                                      "invalid_request_object",
                                      "registration_not_supported",
                                      "request_not_supported",
                                      "request_uri_not_supported"])


class AuthorizationRequest(oauth2.AuthorizationRequest):
    c_param = oauth2.AuthorizationRequest.c_param.copy()
    c_param.update(
        {
            "scope": REQUIRED_LIST_OF_SP_SEP_STRINGS,
            "redirect_uri": SINGLE_REQUIRED_STRING,
            "nonce": SINGLE_OPTIONAL_STRING,
            "display": SINGLE_OPTIONAL_STRING,
            "prompt": OPTIONAL_LIST_OF_STRINGS,
            "max_age": SINGLE_OPTIONAL_INT,
            "ui_locales": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
            "claims_locales": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
            "id_token_hint": SINGLE_OPTIONAL_STRING,
            "login_hint": SINGLE_OPTIONAL_STRING,
            "acr_values": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
            "claims": SINGLE_OPTIONAL_CLAIMSREQ,
            "registration": SINGLE_OPTIONAL_JSON,
            "request": SINGLE_OPTIONAL_STRING,
            "request_uri": SINGLE_OPTIONAL_STRING,
            # "session_state": SINGLE_OPTIONAL_STRING,
            "response_mode": SINGLE_OPTIONAL_STRING,
        }
    )
    c_allowed_values = oauth2.AuthorizationRequest.c_allowed_values.copy()
    c_allowed_values.update({
        "display": ["page", "popup", "touch", "wap"],
        "prompt": ["none", "login", "consent", "select_account"]
    })

    def verify(self, **kwargs):
        """Authorization Request parameters that are OPTIONAL in the OAuth 2.0
        specification MAY be included in the OpenID Request Object without also
        passing them as OAuth 2.0 Authorization Request parameters, with one
        exception: The scope parameter MUST always be present in OAuth 2.0
        Authorization Request parameters.
        All parameter values that are present both in the OAuth 2.0
        Authorization Request and in the OpenID Request Object MUST exactly
        match."""
        super(AuthorizationRequest, self).verify(**kwargs)

        args = {}
        for arg in ["keyjar", "opponent_id", "sender"]:
            try:
                args[arg] = kwargs[arg]
            except KeyError:
                pass

        if "opponent_id" not in kwargs:
            args["opponent_id"] = self["client_id"]

        if "request" in self:
            if isinstance(self["request"], six.string_types):
                # Try to decode the JWT, checks the signature
                oidr = OpenIDRequest().from_jwt(str(self["request"]), **args)

                # verify that nothing is change in the original message
                for key, val in oidr.items():
                    if key in self:
                        if self[key] != val:
                            raise ValueError('{} != {}'.format(self[key], val))

                # replace the JWT with the parsed and verified instance
                self["request"] = oidr

        if "id_token_hint" in self:
            if isinstance(self["id_token_hint"], six.string_types):
                idt = IdToken().from_jwt(str(self["id_token_hint"]), **args)
                self["id_token_hint"] = idt

        if "response_type" not in self:
            raise MissingRequiredAttribute("response_type missing", self)

        _rt = self["response_type"]
        if "id_token" in _rt:
            if "nonce" not in self:
                raise MissingRequiredAttribute("Nonce missing", self)
            else:
                try:
                    if self['nonce'] != kwargs['nonce']:
                        raise ValueError(
                            'Nonce in id_token not matching nonce in authz '
                            'request')
                except KeyError:
                    pass

        if "openid" not in self.get("scope", []):
            raise MissingRequiredValue("openid not in scope", self)

        if "offline_access" in self.get("scope", []):
            if "prompt" not in self or "consent" not in self["prompt"]:
                raise MissingRequiredValue("consent in prompt", self)

        if "prompt" in self:
            if "none" in self["prompt"] and len(self["prompt"]) > 1:
                raise InvalidRequest("prompt none combined with other value",
                                     self)

        return True


class AccessTokenRequest(oauth2.AccessTokenRequest):
    c_param = oauth2.AccessTokenRequest.c_param.copy()
    c_param.update({"client_assertion_type": SINGLE_OPTIONAL_STRING,
                    "client_assertion": SINGLE_OPTIONAL_STRING})
    c_default = {"grant_type": "authorization_code"}
    c_allowed_values = {
        "client_assertion_type": [
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"],
    }


class AddressClaim(Message):
    c_param = {"formatted": SINGLE_OPTIONAL_STRING,
               "street_address": SINGLE_OPTIONAL_STRING,
               "locality": SINGLE_OPTIONAL_STRING,
               "region": SINGLE_OPTIONAL_STRING,
               "postal_code": SINGLE_OPTIONAL_STRING,
               "country": SINGLE_OPTIONAL_STRING}


class OpenIDSchema(ResponseMessage):
    c_param = ResponseMessage.c_param.copy()
    c_param.update(
        {
            "sub": SINGLE_REQUIRED_STRING,
            "name": SINGLE_OPTIONAL_STRING,
            "given_name": SINGLE_OPTIONAL_STRING,
            "family_name": SINGLE_OPTIONAL_STRING,
            "middle_name": SINGLE_OPTIONAL_STRING,
            "nickname": SINGLE_OPTIONAL_STRING,
            "preferred_username": SINGLE_OPTIONAL_STRING,
            "profile": SINGLE_OPTIONAL_STRING,
            "picture": SINGLE_OPTIONAL_STRING,
            "website": SINGLE_OPTIONAL_STRING,
            "email": SINGLE_OPTIONAL_STRING,
            "email_verified": SINGLE_OPTIONAL_BOOLEAN,
            "gender": SINGLE_OPTIONAL_STRING,
            "birthdate": SINGLE_OPTIONAL_STRING,
            "zoneinfo": SINGLE_OPTIONAL_STRING,
            "locale": SINGLE_OPTIONAL_STRING,
            "phone_number": SINGLE_OPTIONAL_STRING,
            "phone_number_verified": SINGLE_OPTIONAL_BOOLEAN,
            "address": OPTIONAL_ADDRESS,
            "updated_at": SINGLE_OPTIONAL_INT,
            "_claim_names": OPTIONAL_MESSAGE,
            "_claim_sources": OPTIONAL_MESSAGE
        })

    def verify(self, **kwargs):
        super(OpenIDSchema, self).verify(**kwargs)

        if "birthdate" in self:
            # Either YYYY-MM-DD or just YYYY or 0000-MM-DD
            try:
                time.strptime(self["birthdate"], "%Y-%m-%d")
            except ValueError:
                try:
                    time.strptime(self["birthdate"], "%Y")
                except ValueError:
                    try:
                        time.strptime(self["birthdate"], "0000-%m-%d")
                    except ValueError:
                        raise VerificationError("Birthdate format error", self)

        if any(val is None for val in self.values()):
            return False

        return True


class RegistrationRequest(Message):
    c_param = {
        "redirect_uris": REQUIRED_LIST_OF_STRINGS,
        "response_types": OPTIONAL_LIST_OF_STRINGS,
        "grant_types": OPTIONAL_LIST_OF_STRINGS,
        "application_type": SINGLE_OPTIONAL_STRING,
        "contacts": OPTIONAL_LIST_OF_STRINGS,
        "client_name": SINGLE_OPTIONAL_STRING,
        "logo_uri": SINGLE_OPTIONAL_STRING,
        "client_uri": SINGLE_OPTIONAL_STRING,
        "policy_uri": SINGLE_OPTIONAL_STRING,
        "tos_uri": SINGLE_OPTIONAL_STRING,
        "jwks": SINGLE_OPTIONAL_DICT,
        "jwks_uri": SINGLE_OPTIONAL_STRING,
        "sector_identifier_uri": SINGLE_OPTIONAL_STRING,
        "subject_type": SINGLE_OPTIONAL_STRING,
        "id_token_signed_response_alg": SINGLE_OPTIONAL_STRING,
        "id_token_encrypted_response_alg": SINGLE_OPTIONAL_STRING,
        "id_token_encrypted_response_enc": SINGLE_OPTIONAL_STRING,
        "userinfo_signed_response_alg": SINGLE_OPTIONAL_STRING,
        "userinfo_encrypted_response_alg": SINGLE_OPTIONAL_STRING,
        "userinfo_encrypted_response_enc": SINGLE_OPTIONAL_STRING,
        "request_object_signing_alg": SINGLE_OPTIONAL_STRING,
        "request_object_encryption_alg": SINGLE_OPTIONAL_STRING,
        "request_object_encryption_enc": SINGLE_OPTIONAL_STRING,
        "token_endpoint_auth_method": SINGLE_OPTIONAL_STRING,
        "token_endpoint_auth_signing_alg": SINGLE_OPTIONAL_STRING,
        "default_max_age": SINGLE_OPTIONAL_INT,
        "require_auth_time": OPTIONAL_LOGICAL,
        "default_acr_values": OPTIONAL_LIST_OF_STRINGS,
        "initiate_login_uri": SINGLE_OPTIONAL_STRING,
        "request_uris": OPTIONAL_LIST_OF_STRINGS,
        # "client_id": SINGLE_OPTIONAL_STRING,
        # "client_secret": SINGLE_OPTIONAL_STRING,
        # "access_token": SINGLE_OPTIONAL_STRING,
        "post_logout_redirect_uris": OPTIONAL_LIST_OF_STRINGS,
    }
    c_default = {"application_type": "web", "response_types": ["code"]}
    c_allowed_values = {"application_type": ["native", "web"],
                        "subject_type": ["public", "pairwise"]}

    def verify(self, **kwargs):
        super(RegistrationRequest, self).verify(**kwargs)

        if "initiate_login_uri" in self:
            if not self["initiate_login_uri"].startswith("https:"):
                raise ValueError('Wrong scheme')

        for param in ["request_object_encryption",
                      "id_token_encrypted_response",
                      "userinfo_encrypted_response"]:
            alg_param = "%s_alg" % param
            enc_param = "%s_enc" % param
            if alg_param in self:
                if enc_param not in self:
                    self[enc_param] = "A128CBC-HS256"

            # both or none
            if enc_param in self:
                if alg_param not in self:
                    raise MissingRequiredAttribute('alg_param')

        if "token_endpoint_auth_signing_alg" in self:
            if self["token_endpoint_auth_signing_alg"] == "none":
                raise ValueError('"none" not allowed')

        return True


class RegistrationResponse(ResponseMessage):
    """
    Response to client_register registration requests
    """
    c_param = ResponseMessage.c_param.copy()
    c_param.update(
        {
            "client_id": SINGLE_REQUIRED_STRING,
            "client_secret": SINGLE_OPTIONAL_STRING,
            "registration_access_token": SINGLE_OPTIONAL_STRING,
            "registration_client_uri": SINGLE_OPTIONAL_STRING,
            "client_id_issued_at": SINGLE_OPTIONAL_INT,
            "client_secret_expires_at": SINGLE_OPTIONAL_INT
        })
    c_param.update(RegistrationRequest.c_param)

    def verify(self, **kwargs):
        """
        Implementations MUST either return both a Client Configuration Endpoint
        and a Registration Access Token or neither of them.
        :param kwargs:
        :return: True if the message is OK otherwise False
        """
        super(RegistrationResponse, self).verify(**kwargs)

        has_reg_uri = "registration_client_uri" in self
        has_reg_at = "registration_access_token" in self
        if has_reg_uri != has_reg_at:
            raise VerificationError((
                "Only one of registration_client_uri"
                " and registration_access_token present"), self)

        return True


class ClientRegistrationErrorResponse(oauth2.ResponseMessage):
    c_allowed_values = {"error": ["invalid_redirect_uri",
                                  "invalid_client_metadata",
                                  "invalid_configuration_parameter"]}


class IdToken(OpenIDSchema):
    c_param = OpenIDSchema.c_param.copy()
    c_param.update({
        "iss": SINGLE_REQUIRED_STRING,
        "sub": SINGLE_REQUIRED_STRING,
        "aud": REQUIRED_LIST_OF_STRINGS,  # Array of strings or string
        "exp": SINGLE_REQUIRED_INT,
        "iat": SINGLE_REQUIRED_INT,
        "auth_time": SINGLE_OPTIONAL_INT,
        "nonce": SINGLE_OPTIONAL_STRING,
        "at_hash": SINGLE_OPTIONAL_STRING,
        "c_hash": SINGLE_OPTIONAL_STRING,
        "acr": SINGLE_OPTIONAL_STRING,
        "amr": OPTIONAL_LIST_OF_STRINGS,
        "azp": SINGLE_OPTIONAL_STRING,
        "sub_jwk": SINGLE_OPTIONAL_STRING
    })
    hashable = {'access_token': 'at_hash', 'code': 'c_hash'}

    def val_hash(self, alg):
        halg = "HS%s" % alg[-3:]

        for attr, hash_attr in self.hashable.items():
            try:
                self[hash_attr] = jws.left_hash(as_unicode(self[attr]), halg)
            except KeyError:
                pass
            else:
                del self[attr]

    def pack_init(self, lifetime=0):
        self['iat'] = utc_time_sans_frac()
        if lifetime:
            self['exp'] = self['iat'] + lifetime

    def pack(self, alg='', **kwargs):
        self.val_hash(alg)

        if 'lifetime' in kwargs:
            self.pack_init(kwargs['lifetime'])
        else:
            self.pack_init()

        if 'jti' in self.c_param:
            try:
                _jti = kwargs['jti']
            except KeyError:
                _jti = uuid.uuid4().hex

            self['jti'] = _jti

    def to_jwt(self, key=None, algorithm="", lev=0, lifetime=0):
        self.pack(alg=algorithm, lifetime=lifetime)
        return Message.to_jwt(self, key=key, algorithm=algorithm, lev=lev)

    def verify(self, **kwargs):
        super(IdToken, self).verify(**kwargs)

        try:
            if kwargs['iss'] != self['iss']:
                raise IssuerMismatch(
                    '{} != {}'.format(kwargs['iss'], self['iss']))
        except KeyError:
            pass

        if "aud" in self:
            if "client_id" in kwargs:
                # check that I'm among the recipients
                if kwargs["client_id"] not in self["aud"]:
                    raise NotForMe(
                        "{} not in aud:{}".format(kwargs["client_id"],
                                                  self["aud"]), self)

            # Then azp has to be present and be one of the aud values
            if len(self["aud"]) > 1:
                if "azp" in self:
                    if self["azp"] not in self["aud"]:
                        raise VerificationError(
                            "Mismatch between azp and aud claims", self)
                else:
                    raise VerificationError("azp missing", self)

        if "azp" in self:
            if "client_id" in kwargs:
                if kwargs["client_id"] != self["azp"]:
                    raise NotForMe(
                        "{} != azp:{}".format(kwargs["client_id"],
                                              self["azp"]), self)

        _now = time_util.utc_time_sans_frac()

        try:
            _skew = kwargs['skew']
        except KeyError:
            _skew = 0

        try:
            _exp = self['exp']
        except KeyError:
            raise MissingRequiredAttribute('exp')
        else:
            if (_now - _skew) > _exp:
                raise EXPError('Invalid expiration time')

        try:
            _storage_time = kwargs['nonce_storage_time']
        except KeyError:
            _storage_time = NONCE_STORAGE_TIME

        try:
            _iat = self['iat']
        except KeyError:
            raise MissingRequiredAttribute('iat')
        else:
            if (_iat + _storage_time) < (_now - _skew):
                raise IATError('Issued too long ago')

        if 'nonce' in kwargs and 'nonce' in self:
            if kwargs['nonce'] != self['nonce']:
                raise ValueError('Not the same nonce')

        return True


class MessageWithIdToken(Message):
    c_param = {"id_token": SINGLE_REQUIRED_IDTOKEN}

    def verify(self, **kwargs):
        super(MessageWithIdToken, self).verify(**kwargs)
        if "id_token" in self:
            # Try to decode the JWT, checks the signature
            args = {}
            for arg in ID_TOKEN_VERIFY_ARGS:
                try:
                    args[arg] = kwargs[arg]
                except KeyError:
                    pass
            idt = IdToken().from_jwt(str(self["id_token"]), **args)
            if not idt.verify(**kwargs):
                return False

            # replace the JWT with the IdToken instance
            self["id_token"] = idt

        return True


class RefreshSessionRequest(MessageWithIdToken):
    c_param = MessageWithIdToken.c_param.copy()
    c_param.update({"redirect_url": SINGLE_REQUIRED_STRING,
                    "state": SINGLE_REQUIRED_STRING})


class RefreshSessionResponse(MessageWithIdToken, ResponseMessage):
    c_param = MessageWithIdToken.c_param.copy()
    c_param.update(ResponseMessage.c_param.copy())
    c_param.update({"state": SINGLE_REQUIRED_STRING})


class CheckSessionRequest(MessageWithIdToken):
    pass


class CheckIDRequest(Message):
    c_param = {"access_token": SINGLE_REQUIRED_STRING}


class EndSessionRequest(Message):
    c_param = {
        "id_token_hint": SINGLE_OPTIONAL_IDTOKEN,
        "post_logout_redirect_uri": SINGLE_OPTIONAL_STRING,
        "state": SINGLE_OPTIONAL_STRING
    }

    def verify(self, **kwargs):
        super(EndSessionRequest, self).verify(**kwargs)
        if "id_token_hint" in self:
            # Try to decode the JWT, checks the signature
            args = {}
            for arg in ID_TOKEN_VERIFY_ARGS:
                try:
                    args[arg] = kwargs[arg]
                except KeyError:
                    pass
            idt = IdToken().from_jwt(str(self["id_token_hint"]), **args)
            if not idt.verify(**kwargs):
                return False

            # replace the JWT with the IdToken instance
            self["id_token_hint"] = idt

        return True


class EndSessionResponse(ResponseMessage):
    c_param = ResponseMessage.c_param.copy()
    c_param.update({"state": SINGLE_OPTIONAL_STRING})


class Claims(Message):
    # c_param = {"*": SINGLE_OPTIONAL_JSON_CONV}
    pass


class ClaimsRequest(Message):
    c_param = {
        "userinfo": OPTIONAL_MULTIPLE_Claims,
        "id_token": OPTIONAL_MULTIPLE_Claims
    }


class OpenIDRequest(AuthorizationRequest):
    pass


class ProviderConfigurationResponse(ResponseMessage):
    c_param = ResponseMessage.c_param.copy()
    c_param.update({
        "issuer": SINGLE_REQUIRED_STRING,
        "authorization_endpoint": SINGLE_REQUIRED_STRING,
        "token_endpoint": SINGLE_OPTIONAL_STRING,
        "userinfo_endpoint": SINGLE_OPTIONAL_STRING,
        "jwks_uri": SINGLE_REQUIRED_STRING,
        "registration_endpoint": SINGLE_OPTIONAL_STRING,
        "scopes_supported": OPTIONAL_LIST_OF_STRINGS,
        "response_types_supported": REQUIRED_LIST_OF_STRINGS,
        "response_modes_supported": OPTIONAL_LIST_OF_STRINGS,
        "grant_types_supported": OPTIONAL_LIST_OF_STRINGS,
        "acr_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "subject_types_supported": REQUIRED_LIST_OF_STRINGS,
        "id_token_signing_alg_values_supported": REQUIRED_LIST_OF_STRINGS,
        "id_token_encryption_alg_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "id_token_encryption_enc_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "userinfo_signing_alg_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "userinfo_encryption_alg_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "userinfo_encryption_enc_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "request_object_signing_alg_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "request_object_encryption_alg_values_supported":
            OPTIONAL_LIST_OF_STRINGS,
        "request_object_encryption_enc_values_supported":
            OPTIONAL_LIST_OF_STRINGS,
        "token_endpoint_auth_methods_supported": OPTIONAL_LIST_OF_STRINGS,
        "token_endpoint_auth_signing_alg_values_supported":
            OPTIONAL_LIST_OF_STRINGS,
        "display_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "claim_types_supported": OPTIONAL_LIST_OF_STRINGS,
        "claims_supported": OPTIONAL_LIST_OF_STRINGS,
        "service_documentation": SINGLE_OPTIONAL_STRING,
        "claims_locales_supported": OPTIONAL_LIST_OF_STRINGS,
        "ui_locales_supported": OPTIONAL_LIST_OF_STRINGS,
        "claims_parameter_supported": SINGLE_OPTIONAL_BOOLEAN,
        "request_parameter_supported": SINGLE_OPTIONAL_BOOLEAN,
        "request_uri_parameter_supported": SINGLE_OPTIONAL_BOOLEAN,
        "require_request_uri_registration": SINGLE_OPTIONAL_BOOLEAN,
        "op_policy_uri": SINGLE_OPTIONAL_STRING,
        "op_tos_uri": SINGLE_OPTIONAL_STRING,
        "check_session_iframe": SINGLE_OPTIONAL_STRING,
        "end_session_endpoint": SINGLE_OPTIONAL_STRING,
        # "jwk_encryption_url": SINGLE_OPTIONAL_STRING,
        # "x509_url": SINGLE_REQUIRED_STRING,
        # "x509_encryption_url": SINGLE_OPTIONAL_STRING,
    })
    c_default = {"version": "3.0",
                 "token_endpoint_auth_methods_supported": [
                     "client_secret_basic"],
                 "claims_parameter_supported": False,
                 "request_parameter_supported": False,
                 "request_uri_parameter_supported": True,
                 "require_request_uri_registration": True,
                 "grant_types_supported": ["authorization_code", "implicit"]}

    def verify(self, **kwargs):
        super(ProviderConfigurationResponse, self).verify(**kwargs)

        if "scopes_supported" in self:
            if "openid" not in self["scopes_supported"]:
                raise MissingRequiredValue
            for scope in self["scopes_supported"]:
                check_char_set(scope, SCOPE_CHARSET)

        parts = urlparse(self["issuer"])
        if parts.scheme != "https":
            raise SchemeError("Not HTTPS")

        if not parts.query and not parts.fragment:
            pass
        else:
            raise ValueError('Issuer ID invalid')

        if any("code" in rt for rt in self[
            "response_types_supported"]) and "token_endpoint" not in self:
            raise MissingRequiredAttribute("token_endpoint")

        return True


# According to RFC 7519 all claims are optional
class JsonWebToken(Message):
    c_param = {
        "iss": SINGLE_OPTIONAL_STRING,
        "sub": SINGLE_OPTIONAL_STRING,
        "aud": OPTIONAL_LIST_OF_STRINGS,  # Array of strings or string
        "exp": SINGLE_OPTIONAL_INT,
        "nbf": SINGLE_OPTIONAL_INT,
        "iat": SINGLE_OPTIONAL_INT,
        "jti": SINGLE_OPTIONAL_STRING,
    }

    def verify(self, **kwargs):
        super(JsonWebToken, self).verify(**kwargs)

        _now = utc_time_sans_frac()

        try:
            _skew = kwargs['skew']
        except KeyError:
            _skew = 0

        try:
            _exp = self['exp']
        except KeyError:
            pass
        else:
            if (_now - _skew) > _exp:
                raise EXPError('Invalid expiration time')

        try:
            _nbf = self['nbf']
        except KeyError:
            pass
        else:
            if _nbf > (_now - _skew):
                raise EXPError('Not valid yet')

        try:
            _aud = self['aud']
        except KeyError:
            pass
        else:
            try:
                if kwargs['aud'] not in _aud:
                    raise NotForMe('Not among intended audience')
            except KeyError:
                pass

        return True


class AuthnToken(JsonWebToken):
    c_param = {
        "iss": SINGLE_REQUIRED_STRING,
        "sub": SINGLE_REQUIRED_STRING,
        "aud": REQUIRED_LIST_OF_STRINGS,  # Array of strings or string
        "jti": SINGLE_REQUIRED_STRING,
        "exp": SINGLE_REQUIRED_INT,
        "iat": SINGLE_OPTIONAL_INT,
    }


def jwt_deser(val, sformat="json"):
    if sformat == "urlencoded":
        sformat = "json"
    if sformat in ["dict", "json"]:
        if not isinstance(val, six.string_types):
            val = json.dumps(val)
            sformat = "json"
    return JsonWebToken().deserialize(val, sformat)


SINGLE_OPTIONAL_JWT = (Message, False, msg_ser, jwt_deser, False)


class UserInfoErrorResponse(oauth2.ResponseMessage):
    c_allowed_values = {"error": ["invalid_schema", "invalid_request",
                                  "invalid_token", "insufficient_scope"]}


class DiscoveryRequest(Message):
    c_param = {"resource": SINGLE_REQUIRED_STRING,
               "rel": SINGLE_REQUIRED_STRING}


class Link(Message):
    """
    https://tools.ietf.org/html/rfc5988
    """
    c_param = {
        "rel": SINGLE_REQUIRED_STRING,
        "type": SINGLE_OPTIONAL_STRING,
        "href": SINGLE_OPTIONAL_STRING,
        "titles": SINGLE_OPTIONAL_DICT,
        "properties": SINGLE_OPTIONAL_DICT
    }


def _l_deser(val, sformat):
    if isinstance(val, Link):
        return val
    elif sformat in ["dict", "json"]:
        if not isinstance(val, str):
            val = json.dumps(val)
            sformat = "json"
    return Link().deserialize(val, sformat)


def link_deser(val, sformat="urlencoded"):
    if isinstance(val, list):
        return [_l_deser(v, sformat) for v in val]
    else:
        return _l_deser(val, sformat)


def link_ser(inst, sformat, lev=0):
    if sformat in ["urlencoded", "json"]:
        if isinstance(inst, dict):
            if sformat == 'json':
                res = json.dumps(inst)
            else:
                res = urlencode([(k, v) for k, v in inst.items()])
        elif isinstance(inst, Link):
            res = inst.serialize(sformat, lev)
        else:
            res = inst
    elif sformat == "dict":
        if isinstance(inst, Link):
            res = inst.serialize(sformat, lev)
        elif isinstance(inst, dict):
            res = inst
        elif isinstance(inst, str):  # Iff ID Token
            res = inst
        else:
            raise MessageException("Wrong type: %s" % type(inst))
    else:
        raise OidcMsgError("Unknown sformat", inst)

    return res


def link_list_ser(inst, sformat, lev=0):
    if isinstance(inst, list):
        return [link_ser(v, sformat) for v in inst]
    else:
        return link_ser(inst, sformat)


REQUIRED_LINKS = ([Link], True, link_list_ser, link_deser, False)


class JRD(ResponseMessage):
    """
    JSON Resource Descriptor https://tools.ietf.org/html/rfc7033#section-4.4
    """
    c_param = {
        "subject": SINGLE_OPTIONAL_STRING,
        "aliases": OPTIONAL_LIST_OF_STRINGS,
        "properties": SINGLE_OPTIONAL_DICT,
        "links": REQUIRED_LINKS
    }


class WebFingerRequest(Message):
    c_param = {
        "resource": SINGLE_REQUIRED_STRING,
        "rel": SINGLE_REQUIRED_STRING
    }
    c_default = {"rel": "http://openid.net/specs/connect/1.0/issuer"}


class ResourceRequest(Message):
    c_param = {"access_token": SINGLE_OPTIONAL_STRING}


SCOPE2CLAIMS = {
    "openid": ["sub"],
    "profile": ["name", "given_name", "family_name", "middle_name",
                "nickname", "profile", "picture", "website", "gender",
                "birthdate", "zoneinfo", "locale", "updated_at",
                "preferred_username"],
    "email": ["email", "email_verified"],
    "address": ["address"],
    "phone": ["phone_number", "phone_number_verified"],
    "offline_access": []
}


def scope2claims(scopes):
    res = {}
    for scope in scopes:
        try:
            claims = dict([(name, None) for name in SCOPE2CLAIMS[scope]])
            res.update(claims)
        except KeyError:
            continue
    return res


def factory(msgtype, **kwargs):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, Message):
            try:
                if obj.__name__ == msgtype:
                    return obj(**kwargs)
            except AttributeError:
                pass

    # Fall back to basic OAuth2 messages
    return oauth2.factory(msgtype, **kwargs)


def make_openid_request(arq, keys=None, userinfo_claims=None,
                        idtoken_claims=None, request_object_signing_alg=None,
                        **kwargs):
    """
    Construct the JWT to be passed by value (the request parameter) or by
    reference (request_uri).
    The request will be signed

    :param arq: The Authorization request
    :param keys: Keys to use for signing/encrypting
    :param userinfo_claims: UserInfo claims
    :param idtoken_claims: IdToken claims
    :param request_object_signing_alg: Which signing algorithm to use
    :return: JWT encoded OpenID request
    """

    oir_args = {}
    for prop in OpenIDRequest.c_param.keys():
        try:
            oir_args[prop] = arq[prop]
        except KeyError:
            pass

    for attr in ["scope", "response_type"]:
        if attr in oir_args:
            oir_args[attr] = " ".join(oir_args[attr])

    c_args = {}
    if userinfo_claims is not None:
        # UserInfoClaims
        c_args["userinfo"] = Claims(**userinfo_claims)

    if idtoken_claims is not None:
        # IdTokenClaims
        c_args["id_token"] = Claims(**idtoken_claims)

    if c_args:
        oir_args["claims"] = ClaimsRequest(**c_args)

    oir = OpenIDRequest(**oir_args)

    return oir.to_jwt(key=keys, algorithm=request_object_signing_alg)


def claims_match(value, claimspec):
    """
    Implements matching according to section 5.5.1 of
    http://openid.net/specs/openid-connect-core-1_0.html
    The lack of value is not checked here.
    Also the text doesn't prohibit claims specification having both 'value' 
    and 'values'.

    :param value: single value or list of values
    :param claimspec: None or a dictionary with 'essential', 'value' or 'values'
        as keys
    :return: Boolean
    """
    if claimspec is None:  # match anything
        return True

    matched = False
    for key, val in claimspec.items():
        if key == "value":
            if value == val:
                matched = True
        elif key == "values":
            if value in val:
                matched = True
        elif key == 'essential':
            # Whether it's essential or not doesn't change anything here
            continue

        if matched:
            break

    if matched is False:
        if list(claimspec.keys()) == ['essential']:
            return True

    return matched
