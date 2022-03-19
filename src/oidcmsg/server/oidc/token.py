import logging

from oidcmsg import oidc
from oidcmsg.message import Message
from oidcmsg.oidc import TokenErrorResponse
from oidcmsg.server import oauth2
from oidcmsg.server.oauth2.token import TokenEndpointHelper
from oidcmsg.server.oidc.backchannel_authentication import CIBATokenHelper
from oidcmsg.server.oidc.token_helper import AccessTokenHelper
from oidcmsg.server.oidc.token_helper import RefreshTokenHelper

logger = logging.getLogger(__name__)


class Token(oauth2.token.Token):
    request_cls = Message
    response_cls = oidc.AccessTokenResponse
    error_cls = TokenErrorResponse
    request_format = "urlencoded"
    request_placement = "body"
    response_format = "json"
    response_placement = "body"
    endpoint_name = "token_endpoint"
    name = "token"
    default_capabilities = None
    provider_info_attributes = {
        "token_endpoint_auth_methods_supported": ['client_secret_post', 'client_secret_basic',
                                                  'client_secret_jwt', 'private_key_jwt'],
        "token_endpoint_auth_signing_alg_values_supported": None
    }
    auth_method_attribute = "token_endpoint_auth_methods_supported"
    helper_by_grant_type = {
        "authorization_code": AccessTokenHelper,
        "refresh_token": RefreshTokenHelper,
        "urn:openid:params:grant-type:ciba": CIBATokenHelper
    }
