from oidcmsg.util import get_http_params


def test_get_http_params():
    conf = {
        "httpc_params": {"verify": False},
        "verify": True,

    }
    _params = get_http_params(conf)
    assert _params == {"verify": False}
