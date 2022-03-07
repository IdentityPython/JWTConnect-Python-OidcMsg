import pytest
from cryptojwt.jwt import utc_time_sans_frac

from oidcmsg.exception import MissingAttribute
from oidcmsg.oidc.backchannel_authentication import AuthenticationRequest
from oidcmsg.oidc.backchannel_authentication import AuthenticationRequestJWT
from oidcmsg.util import rndstr


def test_1():
    areq = AuthenticationRequest(
        scope=["openid"],
        client_notification_token=rndstr(32),
        login_hint="foobar@example.com"
    )

    areq.verify(mode="ping")


def test_2():
    areq = AuthenticationRequest(
        scope=["openid"],
        login_hint="foobar@example.com"
    )

    with pytest.raises(MissingAttribute):
        areq.verify(mode="ping")


def test_3():
    now = utc_time_sans_frac()
    areq = AuthenticationRequestJWT(
        scope=["openid"],
        client_notification_token=rndstr(32),
        login_hint="foobar@example.com",
        iss="https://rp.example.com",
        aud=["https://op.example.com"],
        iat=now,
        exp=now + 3600,
        nbf=now + 30,
        jti=rndstr(32)
    )

    areq.verify(mode="ping", issuer="https://op.example.com",
                client_id="https://rp.example.com")


def test_4():
    now = utc_time_sans_frac()
    areq = AuthenticationRequestJWT(
        scope=["openid"],
        login_hint="foobar@example.com",
        iss="https://rp.example.com",
        aud=["https://op.example.com"],
        iat=now,
        exp=now + 3600,
        nbf=now + 30,
        jti=rndstr(32)
    )

    with pytest.raises(MissingAttribute):
        areq.verify(mode="ping")
