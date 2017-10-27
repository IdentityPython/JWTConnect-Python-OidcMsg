import inspect
import logging
import sys

from oicmsg.exception import VerificationError
from oicmsg.message import Message
from oicmsg.message import OPTIONAL_LIST_OF_SP_SEP_STRINGS
from oicmsg.message import OPTIONAL_LIST_OF_STRINGS
from oicmsg.message import REQUIRED_LIST_OF_SP_SEP_STRINGS
from oicmsg.message import REQUIRED_LIST_OF_STRINGS
from oicmsg.message import SINGLE_OPTIONAL_INT
from oicmsg.message import SINGLE_OPTIONAL_STRING
from oicmsg.message import SINGLE_REQUIRED_STRING

logger = logging.getLogger(__name__)


class ErrorResponse(Message):
    c_param = {"error": SINGLE_REQUIRED_STRING,
               "error_description": SINGLE_OPTIONAL_STRING,
               "error_uri": SINGLE_OPTIONAL_STRING}


class AuthorizationErrorResponse(ErrorResponse):
    c_param = ErrorResponse.c_param.copy()
    c_param.update({"state": SINGLE_OPTIONAL_STRING})
    c_allowed_values = ErrorResponse.c_allowed_values.copy()
    c_allowed_values.update({"error": ["invalid_request",
                                       "unauthorized_client",
                                       "access_denied",
                                       "unsupported_response_type",
                                       "invalid_scope", "server_error",
                                       "temporarily_unavailable"]})


class TokenErrorResponse(ErrorResponse):
    c_allowed_values = {"error": ["invalid_request", "invalid_client",
                                  "invalid_grant", "unauthorized_client",
                                  "unsupported_grant_type",
                                  "invalid_scope"]}


class AccessTokenRequest(Message):
    c_param = {
        "grant_type": SINGLE_REQUIRED_STRING,
        "code": SINGLE_REQUIRED_STRING,
        "redirect_uri": SINGLE_REQUIRED_STRING,
        "client_id": SINGLE_OPTIONAL_STRING,
        "client_secret": SINGLE_OPTIONAL_STRING,
        'state': SINGLE_OPTIONAL_STRING
    }
    c_default = {"grant_type": "authorization_code"}


class AuthorizationRequest(Message):
    c_param = {
        "response_type": REQUIRED_LIST_OF_SP_SEP_STRINGS,
        "client_id": SINGLE_REQUIRED_STRING,
        "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
        "redirect_uri": SINGLE_OPTIONAL_STRING,
        "state": SINGLE_OPTIONAL_STRING,
    }


class AuthorizationResponse(Message):
    c_param = {
        "code": SINGLE_REQUIRED_STRING,
        "state": SINGLE_OPTIONAL_STRING,
        'iss': SINGLE_OPTIONAL_STRING,
        'client_id': SINGLE_OPTIONAL_STRING
    }

    def verify(self, **kwargs):
        super(AuthorizationResponse, self).verify(**kwargs)

        if 'client_id' in self:
            try:
                if self['client_id'] != kwargs['client_id']:
                    raise VerificationError('client_id mismatch')
            except KeyError:
                logger.info('No client_id to verify against')
                pass
        if 'iss' in self:
            try:
                # Issuer URL for the authorization server issuing the response.
                if self['iss'] != kwargs['iss']:
                    raise VerificationError('Issuer mismatch')
            except KeyError:
                logger.info('No issuer set in the Client config')
                pass

        return True


class AccessTokenResponse(Message):
    c_param = {
        "access_token": SINGLE_REQUIRED_STRING,
        "token_type": SINGLE_REQUIRED_STRING,
        "expires_in": SINGLE_OPTIONAL_INT,
        "refresh_token": SINGLE_OPTIONAL_STRING,
        "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
        "state": SINGLE_OPTIONAL_STRING
    }


class NoneResponse(Message):
    c_param = {
        "state": SINGLE_OPTIONAL_STRING
    }


class ROPCAccessTokenRequest(Message):
    c_param = {
        "grant_type": SINGLE_REQUIRED_STRING,
        "username": SINGLE_OPTIONAL_STRING,
        "password": SINGLE_OPTIONAL_STRING,
        "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS
    }


class CCAccessTokenRequest(Message):
    c_param = {
        "grant_type": SINGLE_REQUIRED_STRING,
        "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS
    }
    c_default = {"grant_type": "client_credentials"}
    c_allowed_values = {"grant_type": ["client_credentials"]}


class RefreshAccessTokenRequest(Message):
    c_param = {
        "grant_type": SINGLE_REQUIRED_STRING,
        "refresh_token": SINGLE_REQUIRED_STRING,
        "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
        "client_id": SINGLE_OPTIONAL_STRING,
        "client_secret": SINGLE_OPTIONAL_STRING
    }
    c_default = {"grant_type": "refresh_token"}
    c_allowed_values = {"grant_type": ["refresh_token"]}


class ResourceRequest(Message):
    c_param = {"access_token": SINGLE_OPTIONAL_STRING}


class ASConfigurationResponse(Message):
    c_param = {
        "issuer": SINGLE_REQUIRED_STRING,
        "authorization_endpoint": SINGLE_OPTIONAL_STRING,
        "token_endpoint": SINGLE_OPTIONAL_STRING,
        "jwks_uri": SINGLE_OPTIONAL_STRING,
        "registration_endpoint": SINGLE_OPTIONAL_STRING,
        "scopes_supported": OPTIONAL_LIST_OF_STRINGS,
        "response_types_supported": REQUIRED_LIST_OF_STRINGS,
        "response_modes_supported": OPTIONAL_LIST_OF_STRINGS,
        "grant_types_supported": REQUIRED_LIST_OF_STRINGS,
        "token_endpoint_auth_methods_supported": OPTIONAL_LIST_OF_STRINGS,
        "token_endpoint_auth_signing_alg_values_supported":
            OPTIONAL_LIST_OF_STRINGS,
        "service_documentation": SINGLE_OPTIONAL_STRING,
        "ui_locales_supported": OPTIONAL_LIST_OF_STRINGS,
        "op_policy_uri": SINGLE_OPTIONAL_STRING,
        "op_tos_uri": SINGLE_OPTIONAL_STRING,
        'revocation_endpoint': SINGLE_OPTIONAL_STRING,
        'introspection_endpoint': SINGLE_OPTIONAL_STRING,
    }
    c_default = {"version": "3.0"}



def factory(msgtype, **kwargs):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, Message):
            try:
                if obj.__name__ == msgtype:
                    return obj(**kwargs)
            except AttributeError:
                pass
