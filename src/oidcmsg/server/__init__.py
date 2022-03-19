# Server specific defaults and a basic Server class
from typing import Any
from typing import Optional
from typing import Union

from cryptojwt import KeyJar

from oidcmsg.impexp import ImpExp
from oidcmsg.server import authz
from oidcmsg.server.client_authn import client_auth_setup
from oidcmsg.server.configure import ASConfiguration
from oidcmsg.server.configure import OPConfiguration
from oidcmsg.server.endpoint import Endpoint
from oidcmsg.server.endpoint_context import EndpointContext
from oidcmsg.server.endpoint_context import get_provider_capabilities
from oidcmsg.server.endpoint_context import init_service
from oidcmsg.server.endpoint_context import init_user_info
from oidcmsg.server.session.manager import create_session_manager
from oidcmsg.server.user_authn.authn_context import populate_authn_broker
from oidcmsg.server.util import allow_refresh_token
from oidcmsg.server.util import build_endpoints
from oidcmsg.server.util import build_endpoints


def do_endpoints(conf, server_get):
    _endpoints = conf.get("endpoint")
    if _endpoints:
        return build_endpoints(_endpoints, server_get=server_get, issuer=conf["issuer"])
    else:
        return {}


class Server(ImpExp):
    parameter = {"endpoint": [Endpoint], "endpoint_context": EndpointContext}

    def __init__(
            self,
            conf: Union[dict, OPConfiguration, ASConfiguration],
            keyjar: Optional[KeyJar] = None,
            cwd: Optional[str] = "",
            cookie_handler: Optional[Any] = None,
            httpc: Optional[Any] = None,
    ):
        ImpExp.__init__(self)
        self.conf = conf
        self.endpoint_context = EndpointContext(
            conf=conf,
            server_get=self.server_get,
            keyjar=keyjar,
            cwd=cwd,
            cookie_handler=cookie_handler,
            httpc=httpc,
        )
        self.endpoint_context.authz = self.do_authz()

        self.do_authentication(self.endpoint_context)

        self.endpoint = do_endpoints(conf, self.server_get)
        _cap = get_provider_capabilities(conf, self.endpoint)

        self.endpoint_context.provider_info = self.endpoint_context.create_providerinfo(_cap)
        self.endpoint_context.do_add_on(endpoints=self.endpoint)

        self.endpoint_context.session_manager = create_session_manager(
            self.server_get,
            self.endpoint_context.th_args,
            sub_func=self.endpoint_context._sub_func,
            conf=self.conf,
        )
        self.endpoint_context.do_userinfo()
        # Must be done after userinfo
        self.do_login_hint_lookup()
        self.endpoint_context.set_remember_token()

        self.do_client_authn_methods()
        for endpoint_name, _ in self.endpoint.items():
            self.endpoint[endpoint_name].server_get = self.server_get

        _token_endp = self.endpoint.get("token")
        if _token_endp:
            _token_endp.allow_refresh = allow_refresh_token(self.endpoint_context)

        self.endpoint_context.claims_interface = init_service(
            conf["claims_interface"], self.server_get
        )

        _id_token_handler = self.endpoint_context.session_manager.token_handler.handler.get(
            "id_token"
        )
        if _id_token_handler:
            self.endpoint_context.provider_info.update(_id_token_handler.provider_info)

    def server_get(self, what, *arg):
        _func = getattr(self, "get_{}".format(what), None)
        if _func:
            return _func(*arg)
        return None

    def get_endpoints(self, *arg):
        return self.endpoint

    def get_endpoint(self, endpoint_name, *arg):
        try:
            return self.endpoint[endpoint_name]
        except KeyError:
            return None

    def get_endpoint_context(self, *arg):
        return self.endpoint_context

    def do_authz(self):
        authz_spec = self.conf.get("authz")
        if authz_spec:
            return init_service(authz_spec, self.server_get)
        else:
            return authz.Implicit(self.server_get)

    def do_authentication(self, target):
        _conf = self.conf.get("authentication")
        if _conf:
            target.authn_broker = populate_authn_broker(
                _conf, self.server_get, target.template_handler
            )
        else:
            target.authn_broker = {}

        target.endpoint_to_authn_method = {}
        for method in target.authn_broker:
            try:
                target.endpoint_to_authn_method[method.action] = method
            except AttributeError:
                pass

    def do_login_hint_lookup(self):
        _conf = self.conf.get("login_hint_lookup")
        if _conf:
            _userinfo = None
            _kwargs = _conf.get("kwargs")
            if _kwargs:
                _userinfo_conf = _kwargs.get("userinfo")
                if _userinfo_conf:
                    _userinfo = init_user_info(_userinfo_conf, self.endpoint_context.cwd)

            if _userinfo is None:
                _userinfo = self.endpoint_context.userinfo

            self.endpoint_context.login_hint_lookup = init_service(_conf)
            self.endpoint_context.login_hint_lookup.userinfo = _userinfo

    def do_client_authn_methods(self):
        self.endpoint_context.client_authn_method = client_auth_setup(self.server_get,
                                                                      self.conf.get(
                                                                          "client_authn_method"))
