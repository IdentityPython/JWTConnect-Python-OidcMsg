from oidcmsg.exception import MissingAttribute
from oidcmsg.exception import ParameterError
from oidcmsg.message import Message
from oidcmsg.message import OPTIONAL_LIST_OF_STRINGS
from oidcmsg.message import REQUIRED_LIST_OF_SP_SEP_STRINGS
from oidcmsg.message import REQUIRED_LIST_OF_STRINGS
from oidcmsg.message import SINGLE_OPTIONAL_INT
from oidcmsg.message import SINGLE_OPTIONAL_STRING
from oidcmsg.message import SINGLE_REQUIRED_INT
from oidcmsg.message import SINGLE_REQUIRED_STRING
from oidcmsg.oauth2 import ResponseMessage


class AuthenticationRequest(Message):
    c_param = {
        "scope": REQUIRED_LIST_OF_SP_SEP_STRINGS,
        "client_notification_token": SINGLE_OPTIONAL_STRING,
        "acr_values": OPTIONAL_LIST_OF_STRINGS,
        "login_hint_token": SINGLE_OPTIONAL_STRING,
        "id_token_hint": SINGLE_OPTIONAL_STRING,
        "login_hint": SINGLE_OPTIONAL_STRING,
        "binding_message": SINGLE_OPTIONAL_STRING,
        "user_code": SINGLE_OPTIONAL_STRING,
        "requested_expiry": SINGLE_OPTIONAL_INT,
        # The ones below are part of client authentication information
        "client_id": SINGLE_OPTIONAL_STRING,
        "client_assertion_type": SINGLE_OPTIONAL_STRING,
        "client_assertion": SINGLE_OPTIONAL_STRING,
    }

    def verify(self, **kwargs):
        _mode = kwargs.get("mode")
        if _mode in ["ping", "push"]:
            if "client_notification_token" not in self:
                raise MissingAttribute(
                    "client_notification_token must be present in ping or push mode")


class AuthenticationRequestJWT(Message):
    c_param = {
        "iss": SINGLE_REQUIRED_STRING,
        "aud": REQUIRED_LIST_OF_STRINGS,  # Array of strings or string
        "exp": SINGLE_REQUIRED_INT,
        "nbf": SINGLE_REQUIRED_INT,
        "iat": SINGLE_REQUIRED_INT,
        "jti": SINGLE_REQUIRED_STRING,
        "scope": REQUIRED_LIST_OF_SP_SEP_STRINGS,
        "client_notification_token": SINGLE_OPTIONAL_STRING,
        "acr_values": OPTIONAL_LIST_OF_STRINGS,
        "login_hint_token": SINGLE_OPTIONAL_STRING,
        "id_token_hint": SINGLE_OPTIONAL_STRING,
        "login_hint": SINGLE_OPTIONAL_STRING,
        "binding_message": SINGLE_OPTIONAL_STRING,
        "user_code": SINGLE_OPTIONAL_STRING,
        "requested_expiry": SINGLE_OPTIONAL_INT,
    }

    def verify(self, **kwargs):
        _mode = kwargs.get("mode")
        if _mode in ["ping", "push"]:
            if "client_notification_token" not in self:
                raise MissingAttribute(
                    "client_notification_token must be present in ping or push mode")

        _iss = kwargs.get("issuer")
        if _iss:
            if _iss not in self["aud"]:
                raise ParameterError("Not among audience")

        _client_id = kwargs.get("client_id")
        if _client_id:
            if _client_id != self["iss"]:
                raise ParameterError("Issuer mismatch")


class AuthenticationRequestResponse(ResponseMessage):
    c_param = {
        "auth_req_id": SINGLE_REQUIRED_STRING,
        "expires_in": SINGLE_REQUIRED_INT,
        "interval": SINGLE_OPTIONAL_INT
    }
    c_default = {"interval": 5}


class TokenRequest(Message):
    c_param = {
        "grant_type": SINGLE_REQUIRED_STRING,
        "auth_req_id": SINGLE_REQUIRED_STRING,
        # The ones below are part of client authentication information
        "client_id": SINGLE_OPTIONAL_STRING,
        "client_assertion_type": SINGLE_OPTIONAL_STRING,
        "client_assertion": SINGLE_OPTIONAL_STRING,
    }
