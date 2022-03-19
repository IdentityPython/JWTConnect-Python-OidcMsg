from oidcmsg.client.service import Service
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc.backchannel_authentication import AuthenticationRequest
from oidcmsg.oidc.backchannel_authentication import AuthenticationResponse


class BackChannelAuthentication(Service):
    """The service that talks to the OIDC Authorization endpoint."""
    msg_type = AuthenticationRequest
    response_cls = AuthenticationResponse
    error_msg = ResponseMessage
    endpoint_name = 'backchannel_authentication_endpoint'
    synchronous = True
    service_name = 'backchannel_authentication'
    response_body_type = 'json'

    def __init__(self, client_get, client_authn_factory=None, conf=None):
        super().__init__(client_get, client_authn_factory, conf=conf)
        self.default_request_args = {'scope': ['openid']}
        self.pre_construct = []
        self.post_construct = []
