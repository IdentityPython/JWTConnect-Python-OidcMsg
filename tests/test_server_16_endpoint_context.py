import copy
import os

from cryptojwt.key_jar import build_keyjar
import pytest

from oidcmsg.server import OPConfiguration
from oidcmsg.server import Server
from oidcmsg.server import do_endpoints
from oidcmsg.server.endpoint import Endpoint
from oidcmsg.server.endpoint_context import EndpointContext
from oidcmsg.server.endpoint_context import get_provider_capabilities
from oidcmsg.server.exception import OidcEndpointError
from oidcmsg.server.session.manager import create_session_manager
from oidcmsg.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcmsg.server.util import allow_refresh_token
from . import full_path

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

KEYJAR = build_keyjar(KEYDEFS)


class Endpoint_1(Endpoint):
    name = "userinfo"
    default_capabilities = {
        "claim_types_supported": ["normal", "aggregated", "distributed"],
        "userinfo_signing_alg_values_supported": None,
        "userinfo_encryption_alg_values_supported": None,
        "userinfo_encryption_enc_values_supported": None,
        "client_authn_method": ["bearer_header", "bearer_body"],
    }


conf = {
    "issuer": "https://example.com/",
    "template_dir": "template",
    "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS, "read_only": True},
    "capabilities": {
        "subject_types_supported": ["public", "pairwise"],
        "grant_types_supported": [
            "authorization_code",
            "implicit",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "refresh_token",
        ],
    },
    "endpoint": {
        "userinfo": {
            "path": "userinfo",
            "class": Endpoint_1,
            "kwargs": {
                "client_authn_method": [
                    "private_key_jwt",
                    "client_secret_jwt",
                    "client_secret_post",
                    "client_secret_basic",
                ]
            }
        }
    },
    "token_handler_args": {
        "jwks_def": {
            "private_path": "private/token_jwks.json",
            "read_only": False,
            "key_defs": [{"type": "oct", "bytes": "24", "use": ["enc"], "kid": "code"}],
        },
        "code": {"kwargs": {"lifetime": 600}},
        "token": {
            "class": "oidcmsg.server.token.jwt_token.JWTToken",
            "kwargs": {
                "lifetime": 3600,
                "add_claims_by_scope": True,
                "aud": ["https://example.org/appl"],
            },
        },
        "refresh": {
            "class": "oidcmsg.server.token.jwt_token.JWTToken",
            "kwargs": {"lifetime": 3600, "aud": ["https://example.org/appl"], },
        },
        "id_token": {"class": "oidcmsg.server.token.id_token.IDToken", "kwargs": {}},
    },
    "userinfo": {
        "class": "oidcmsg.server.user_info.UserInfo",
        "kwargs": {"db_file": full_path("users.json")},
    },
    "claims_interface": {"class": "oidcmsg.server.session.claims.ClaimsInterface", "kwargs": {}},
}


class TestEndpointContext:
    @pytest.fixture(autouse=True)
    def create_endpoint_context(self):
        self.endpoint_context = EndpointContext(
            conf=conf,
            server_get=self.server_get,
            keyjar=KEYJAR,
        )

    def server_get(self, *args):
        if args[0] == "endpoint_context":
            return self.endpoint_context

    def test(self):
        endpoint = do_endpoints(conf, self.server_get)
        _cap = get_provider_capabilities(conf, endpoint)
        pi = self.endpoint_context.create_providerinfo(_cap)
        assert set(pi.keys()) == {'claims_supported', 'issuer', 'version', 'scopes_supported',
                                  'subject_types_supported', 'grant_types_supported'}

    def test_allow_refresh_token(self):
        self.endpoint_context.session_manager = create_session_manager(
            self.server_get,
            self.endpoint_context.th_args,
            sub_func=self.endpoint_context._sub_func,
            conf=conf,
        )

        assert allow_refresh_token(self.endpoint_context)

        # Have the software but is not expected to use it.
        self.endpoint_context.conf["capabilities"]["grant_types_supported"] = [
            "authorization_code",
            "implicit",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
        ]
        assert allow_refresh_token(self.endpoint_context) is False

        # Don't have the software but are expected to use it.
        self.endpoint_context.conf["capabilities"]["grant_types_supported"] = [
            "authorization_code",
            "implicit",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "refresh_token"
        ]
        del self.endpoint_context.session_manager.token_handler.handler["refresh_token"]
        with pytest.raises(OidcEndpointError):
            assert allow_refresh_token(self.endpoint_context) is False


class Tokenish(Endpoint):
    default_capabilities = None
    provider_info_attributes = {
        "token_endpoint_auth_methods_supported": ['client_secret_post', 'client_secret_basic',
                                                  'client_secret_jwt', 'private_key_jwt'],
        "token_endpoint_auth_signing_alg_values_supported": None
    }
    auth_method_attribute = "token_endpoint_auth_methods_supported"


BASEDIR = os.path.abspath(os.path.dirname(__file__))

CONF = {
    "issuer": "https://example.com/",
    "httpc_params": {"verify": False, "timeout": 1},
    "token_expires_in": 600,
    "grant_expires_in": 300,
    "refresh_token_expires_in": 86400,
    "capabilities": {
        "subject_types_supported": ["public", "pairwise"],
        "grant_types_supported": [
            "authorization_code",
            "implicit",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "refresh_token",
        ],
    },
    "keys": {
        "public_path": "jwks.json",
        "key_defs": KEYDEFS,
        "private_path": "own/jwks.json",
        "uri_path": "static/jwks.json",
    },
    "authentication": {
        "anon": {
            "acr": INTERNETPROTOCOLPASSWORD,
            "class": "oidcmsg.server.user_authn.user.NoAuthn",
            "kwargs": {"user": "diana"},
        }
    },
    "template_dir": "template",
}


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"client_authn_method": ['client_secret_jwt', 'private_key_jwt']},
        {"token_endpoint_auth_methods_supported": ['client_secret_jwt', 'private_key_jwt']}
    ]
)
def test_provider_configuration(kwargs):
    conf = copy.deepcopy(CONF)
    conf["endpoint"] = {
        "endpoint": {
            "path": "endpoint",
            "class": Tokenish, "kwargs": kwargs},
    }

    server = Server(OPConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)
    server.endpoint_context.cdb["client_id"] = {}
    _endpoints = do_endpoints(conf, server.server_get)

    _cap = get_provider_capabilities(conf, _endpoints)
    pi = server.endpoint_context.create_providerinfo(_cap)
    assert set(pi.keys()) == {'version', 'acr_values_supported', 'issuer', 'jwks_uri',
                              'scopes_supported', 'grant_types_supported', 'claims_supported',
                              'subject_types_supported', 'token_endpoint_auth_methods_supported',
                              'token_endpoint_auth_signing_alg_values_supported', }

    if kwargs:
        assert pi['token_endpoint_auth_methods_supported'] == ['client_secret_jwt',
                                                               'private_key_jwt']
    else:
        assert pi['token_endpoint_auth_methods_supported'] == ['client_secret_post',
                                                               'client_secret_basic',
                                                               'client_secret_jwt',
                                                               'private_key_jwt']
