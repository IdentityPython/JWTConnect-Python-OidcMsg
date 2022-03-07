from cryptojwt.key_jar import build_keyjar
import pytest

from oidcmsg.server import do_endpoints
from oidcmsg.server import get_capabilities
from oidcmsg.server.endpoint import Endpoint
from oidcmsg.server.endpoint_context import EndpointContext
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
        _cap = get_capabilities(conf, endpoint)
        pi = self.endpoint_context.create_providerinfo(_cap)
        assert set(pi.keys()) == {'claim_types_supported',
                                  'claims_supported',
                                  'client_authn_method',
                                  'issuer',
                                  'scopes_supported',
                                  'userinfo_encryption_alg_values_supported',
                                  'userinfo_encryption_enc_values_supported',
                                  'userinfo_signing_alg_values_supported',
                                  'version'}
