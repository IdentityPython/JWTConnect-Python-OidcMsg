import inspect
import logging
import sys

from oidcmsg.exception import VerificationError
from oidcmsg.message import Message
from oidcmsg.message import OPTIONAL_LIST_OF_SP_SEP_STRINGS
from oidcmsg.message import OPTIONAL_LIST_OF_STRINGS
from oidcmsg.message import REQUIRED_LIST_OF_SP_SEP_STRINGS
from oidcmsg.message import REQUIRED_LIST_OF_STRINGS
from oidcmsg.message import SINGLE_OPTIONAL_INT
from oidcmsg.message import SINGLE_OPTIONAL_STRING
from oidcmsg.message import SINGLE_REQUIRED_STRING

logger = logging.getLogger(__name__)


def is_error_message(msg):
    if 'error' in msg:
        return True
    else:
        return False


class ResponseMessage(Message):
    """
    The basic error response
    """
    c_param = {"error": SINGLE_OPTIONAL_STRING,
               "error_description": SINGLE_OPTIONAL_STRING,
               "error_uri": SINGLE_OPTIONAL_STRING}


class AuthorizationErrorResponse(ResponseMessage):
    """
    Authorization error response.
    """
    c_param = ResponseMessage.c_param.copy()
    c_param.update({"state": SINGLE_OPTIONAL_STRING})
    c_allowed_values = ResponseMessage.c_allowed_values.copy()
    c_allowed_values.update({"error": ["invalid_request",
                                       "unauthorized_client",
                                       "access_denied",
                                       "unsupported_response_type",
                                       "invalid_scope", "server_error",
                                       "temporarily_unavailable"]})


class TokenErrorResponse(ResponseMessage):
    """
    Error response from the token endpoint
    """
    c_allowed_values = {"error": ["invalid_request", "invalid_client",
                                  "invalid_grant", "unauthorized_client",
                                  "unsupported_grant_type",
                                  "invalid_scope"]}


class AccessTokenRequest(Message):
    """
    An access token request
    """
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
    """
    An authorization request
    """
    c_param = {
        "response_type": REQUIRED_LIST_OF_SP_SEP_STRINGS,
        "client_id": SINGLE_REQUIRED_STRING,
        "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
        "redirect_uri": SINGLE_OPTIONAL_STRING,
        "state": SINGLE_OPTIONAL_STRING,
    }


class AuthorizationResponse(ResponseMessage):
    """
    An authorization response.
    If *client_id* is returned in the response it will be checked against
    a client_id value provided when calling the verify method.
    The same with *iss* (issuer).
    """
    c_param = ResponseMessage.c_param.copy()
    c_param.update({
        "code": SINGLE_REQUIRED_STRING,
        "state": SINGLE_OPTIONAL_STRING,
        'iss': SINGLE_OPTIONAL_STRING,
        'client_id': SINGLE_OPTIONAL_STRING
    })

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


class AccessTokenResponse(ResponseMessage):
    """
    Access token response
    """
    c_param = ResponseMessage.c_param.copy()
    c_param.update({
        "access_token": SINGLE_REQUIRED_STRING,
        "token_type": SINGLE_REQUIRED_STRING,
        "expires_in": SINGLE_OPTIONAL_INT,
        "refresh_token": SINGLE_OPTIONAL_STRING,
        "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
        "state": SINGLE_OPTIONAL_STRING
    })


class NoneResponse(ResponseMessage):
    c_param = ResponseMessage.c_param.copy()
    c_param.update({
        "state": SINGLE_OPTIONAL_STRING
    })


class ROPCAccessTokenRequest(Message):
    """
    Resource Owner Password Credentials Grant flow access token request
    """
    c_param = {
        "grant_type": SINGLE_REQUIRED_STRING,
        "username": SINGLE_OPTIONAL_STRING,
        "password": SINGLE_OPTIONAL_STRING,
        "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS
    }


class CCAccessTokenRequest(Message):
    """
    Client Credential grant flow access token request
    """
    c_param = {
        "grant_type": SINGLE_REQUIRED_STRING,
        "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS
    }
    c_default = {"grant_type": "client_credentials"}
    c_allowed_values = {"grant_type": ["client_credentials"]}


class RefreshAccessTokenRequest(Message):
    """
    Access token refresh request
    """
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
    """
    Authorization Server configuration response
    """
    c_param = ResponseMessage.c_param.copy()
    c_param.update({
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
    })
    c_default = {"version": "3.0"}


def factory(msgtype, **kwargs):
    """
    Factory method that can be used to easily instansiate a class instance
    
    :param msgtype: The name of the class 
    :param kwargs: Keyword arguments 
    :return: An instance of the class or None if the name doesn't match any
        known class.
    """
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, Message):
            try:
                if obj.__name__ == msgtype:
                    return obj(**kwargs)
            except AttributeError:
                pass
