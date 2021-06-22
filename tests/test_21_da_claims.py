from cryptojwt import JWT
from cryptojwt.key_jar import init_key_jar
from oidcmsg.oidc.distributed_aggregated_claims import aggregated_claim_set

from oidcmsg.oidc.distributed_aggregated_claims import add_aggregated_claims

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

KEYS = init_key_jar(key_defs=KEYDEFS)


def test_add_aggregated_claims():
    agg_claims = {
        "address": {
            "street_address": "1234 Hollywood Blvd.",
            "locality": "Los Angeles",
            "region": "CA",
            "postal_code": "90210",
            "country": "US"},
        "phone_number": "+1 (310) 123-4567"
    }

    _jwt = JWT(key_jar=KEYS)
    _jws = _jwt.pack(payload=agg_claims)

    _base_claims = {
        "name": "Jane Doe",
        "given_name": "Jane",
        "family_name": "Doe",
        "birthdate": "0000-03-22",
        "eye_color": "blue",
        "email": "janedoe@example.com"
    }

    _claims = add_aggregated_claims(_base_claims, list(agg_claims.keys()), _jws)
    assert "_claim_names" in _claims
    assert "_claim_sources" in _claims


def test_add_two_aggregated_claims():
    _base_claims = {
        "name": "Jane Doe",
        "given_name": "Jane",
        "family_name": "Doe",
        "birthdate": "0000-03-22",
        "eye_color": "blue",
        "email": "janedoe@example.com"
    }

    agg_claims_1 = {
        "address": {
            "street_address": "1234 Hollywood Blvd.",
            "locality": "Los Angeles",
            "region": "CA",
            "postal_code": "90210",
            "country": "US"}
    }

    _jwt = JWT(key_jar=KEYS)
    _jws1 = _jwt.pack(payload=agg_claims_1)

    _claims = add_aggregated_claims(_base_claims, list(agg_claims_1.keys()), _jws1)

    agg_claims_2 = {
        "phone_number": "+1 (310) 123-4567"
    }

    _jws2 = _jwt.pack(payload=agg_claims_2)

    _claims = add_aggregated_claims(_claims, list(agg_claims_2.keys()), _jws2)

    assert "_claim_names" in _claims
    assert _claims["_claim_names"] == {'address': 'src1', 'phone_number': 'src2'}
    assert "_claim_sources" in _claims
    assert set(_claims["_claim_sources"].keys()) == {"src1", "src2"}


def test_extend():
    agg_claims = {
        "address": {
            "street_address": "1234 Hollywood Blvd.",
            "locality": "Los Angeles",
            "region": "CA",
            "postal_code": "90210",
            "country": "US"},
        "phone_number": "+1 (310) 123-4567"
    }

    _jwt = JWT(key_jar=KEYS)
    _jws = _jwt.pack(payload=agg_claims)

    _base_claims = {
        "name": "Jane Doe",
        "given_name": "Jane",
        "family_name": "Doe",
        "birthdate": "0000-03-22",
        "eye_color": "blue",
        "email": "janedoe@example.com"
    }

    _claims = add_aggregated_claims(_base_claims, list(agg_claims.keys()), _jws)

    _claims_set = aggregated_claim_set(_claims, "src1", KEYS)
    assert _claims_set
