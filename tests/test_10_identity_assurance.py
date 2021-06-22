import time
from urllib.parse import quote_plus

from cryptojwt import JWT
from cryptojwt.key_jar import init_key_jar

from oidcmsg.oidc.distributed_aggregated_claims import add_aggregated_claims
from oidcmsg.oidc.distributed_aggregated_claims import aggregated_claim_set
from oidcmsg.oidc.identity_assurance import ClaimsConstructor
from oidcmsg.oidc.identity_assurance import EVIDENCE_TYPE_TO_CLASS
from oidcmsg.oidc.identity_assurance import IDAClaimsRequest
from oidcmsg.oidc.identity_assurance import UserInfoClaimsRequest
from oidcmsg.oidc.identity_assurance import Verification
from oidcmsg.oidc.identity_assurance import VerificationRequest
from oidcmsg.oidc.identity_assurance import VerifiedClaims
from oidcmsg.oidc.identity_assurance import VerifiedClaimsRequest
from oidcmsg.oidc.identity_assurance import from_iso8601_2004_time
from oidcmsg.oidc.identity_assurance import match_verified_claims
from oidcmsg.oidc.identity_assurance import to_iso8601_2004_time
from oidcmsg.oidc.identity_assurance import verification_per_claim
from oidcmsg.time_util import time_sans_frac

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

KEYS = init_key_jar(key_defs=KEYDEFS, issuer_id="https://server.otherop.com")


def test_time_stamp():
    now = time_sans_frac()
    iso = to_iso8601_2004_time()

    d = from_iso8601_2004_time(iso)

    assert now == d


def test_verification_element():
    ve = Verification(trust_framework="TrustAreUs", time=time.time())
    ve_dict1 = ve.to_dict()

    ve = Verification(trust_framework="TrustAreUs")
    ve["time"] = time.time()
    ve_dict2 = ve.to_dict()

    assert ve_dict1 == ve_dict2

    ve = Verification().from_dict(ve_dict1)

    assert ve

    s = "2020-01-11T11:00:00+0100"
    ve_2 = Verification(trust_framework="TrustAreUs")
    ve_2["time"] = s

    assert quote_plus("2020-01-11T11:00:00+0100") in ve_2.to_urlencoded()


def test_verfication_element_from_dict():
    d = {
        "verification": {"trust_framework": "eidas_ial_substantial"},
        "claims": {
            "given_name": "Max",
            "family_name": "Meier",
            "birthdate": "1956-01-28",
            "place_of_birth": {"country": "DE", "locality": "Musterstadt"},
            "nationality": "DE",
            "address": {
                "locality": "Maxstadt",
                "postal_code": "12344",
                "country": "DE",
                "street_address": "An der Sanddüne 22",
            },
        },
    }
    v = VerifiedClaims(**d)
    assert v


def test_userinfo_response():
    resp = {
        "sub": "248289761001",
        "email": "janedoe@example.com",
        "email_verified": True,
        "verified_claims": {
            "verification": {
                "trust_framework": "de_aml",
                "time": "2012-04-23T18:25:43.511+01",
                "verification_process": "676q3636461467647q8498785747q487",
                "evidence": [
                    {
                        "type": "id_document",
                        "method": "pipp",
                        "document": {
                            "type": "idcard",
                            "issuer": {"name": "Stadt Augsburg", "country": "DE"},
                            "number": "53554554",
                            "date_of_issuance": "2012-04-23",
                            "date_of_expiry": "2022-04-22",
                        },
                    }
                ],
            },
            "claims": {"given_name": "Max", "family_name": "Meier", "birthdate": "1956-01-28"},
        },
    }

    v = VerifiedClaims(**resp["verified_claims"])
    assert v
    assert set(v.keys()) == {"verification", "claims"}

    _ver = v["verification"]
    assert isinstance(_ver, Verification)

    assert set(_ver.keys()) == {"trust_framework", "time", "verification_process", "evidence"}
    _evidence = _ver["evidence"]
    assert len(_evidence) == 1
    _evidence_1 = _evidence[0]
    assert _evidence_1["type"] == "id_document"


def test_userinfo_request():
    _request = {
        "userinfo": {
            "verified_claims": {
                "verification": {
                    "trust_framework": None
                },
                "claims": {
                    "given_name": None,
                    "family_name": None,
                    "birthdate": None
                }
            }
        }
    }

    _claims_request = IDAClaimsRequest(**_request)
    assert "userinfo" in _claims_request
    assert isinstance(_claims_request["userinfo"], UserInfoClaimsRequest)
    assert "verified_claims" in _claims_request["userinfo"]
    assert isinstance(_claims_request["userinfo"]["verified_claims"], list)
    assert isinstance(_claims_request["userinfo"]["verified_claims"][0], VerifiedClaimsRequest)
    assert "verification" in _claims_request["userinfo"]["verified_claims"][0]
    assert isinstance(_claims_request["userinfo"]["verified_claims"][0]["verification"],
                      VerificationRequest)

    _verified_claims = _claims_request["userinfo"]["verified_claims"][0]
    assert _verified_claims["verification"]["trust_framework"] is None
    assert _verified_claims["claims"]["given_name"] is None


def test_userinfo_request_essential():
    _request = {
        "userinfo": {
            "verified_claims": {
                "verification": {
                    "trust_framework": None
                },
                "claims": {
                    "given_name": {"essential": True},
                    "family_name": {"essential": True},
                    "birthdate": None
                }
            }
        }
    }

    _claims_request = IDAClaimsRequest(**_request)
    assert "userinfo" in _claims_request
    assert isinstance(_claims_request["userinfo"], UserInfoClaimsRequest)
    assert "verified_claims" in _claims_request["userinfo"]
    assert isinstance(_claims_request["userinfo"]["verified_claims"], list)
    assert isinstance(_claims_request["userinfo"]["verified_claims"][0], VerifiedClaimsRequest)
    assert "verification" in _claims_request["userinfo"]["verified_claims"][0]
    assert isinstance(_claims_request["userinfo"]["verified_claims"][0]["verification"],
                      VerificationRequest)

    _verified_claims = _claims_request["userinfo"]["verified_claims"][0]
    assert _verified_claims["verification"]["trust_framework"] is None
    assert _verified_claims["claims"]["given_name"] == {"essential": True}


def test_userinfo_request_claims_purpose():
    _request = {
        "userinfo": {
            "verified_claims": {
                "verification": {
                    "trust_framework": None
                },
                "claims": {
                    "given_name": {
                        "essential": True,
                        "purpose": "To make communication look more personal"
                    },
                    "family_name": {
                        "essential": True
                    },
                    "birthdate": {
                        "purpose": "To send you best wishes on your birthday"
                    }
                }
            }
        }
    }

    _claims_request = IDAClaimsRequest(**_request)
    assert "userinfo" in _claims_request
    assert isinstance(_claims_request["userinfo"], UserInfoClaimsRequest)
    assert "verified_claims" in _claims_request["userinfo"]
    assert isinstance(_claims_request["userinfo"]["verified_claims"], list)
    assert isinstance(_claims_request["userinfo"]["verified_claims"][0], VerifiedClaimsRequest)
    assert "verification" in _claims_request["userinfo"]["verified_claims"][0]
    assert isinstance(_claims_request["userinfo"]["verified_claims"][0]["verification"],
                      VerificationRequest)

    _verified_claims = _claims_request["userinfo"]["verified_claims"][0]
    assert _verified_claims["verification"]["trust_framework"] is None
    assert _verified_claims["claims"]["given_name"] == {
        "essential": True,
        "purpose": "To make communication look more personal"
    }


def test_request_verification_data():
    _request = {
        "userinfo": {
            "verified_claims": {
                "verification": {
                    "trust_framework": None,
                    "time": None
                },
                "claims": {
                    "given_name": None,
                    "family_name": None,
                    "birthdate": None
                }
            }
        }
    }
    _claims_request = IDAClaimsRequest(**_request)

    assert "userinfo" in _claims_request
    assert isinstance(_claims_request["userinfo"], UserInfoClaimsRequest)
    assert "verified_claims" in _claims_request["userinfo"]
    assert isinstance(_claims_request["userinfo"]["verified_claims"], list)
    assert isinstance(_claims_request["userinfo"]["verified_claims"][0], VerifiedClaimsRequest)
    assert "verification" in _claims_request["userinfo"]["verified_claims"][0]
    assert isinstance(_claims_request["userinfo"]["verified_claims"][0]["verification"],
                      VerificationRequest)

    _verified_claims = _claims_request["userinfo"]["verified_claims"][0]
    assert set(_verified_claims["verification"].keys()) == {"trust_framework", "time"}


def test_request_verification_evidence():
    _request = {
        "userinfo": {
            "verified_claims": {
                "verification": {
                    "trust_framework": None,
                    "time": None,
                    "evidence": [
                        {
                            "type": {
                                "value": "id_document"
                            },
                            "method": None,
                            "document": {
                                "type": None
                            }
                        }
                    ]
                },
                "claims": {
                    "given_name": None,
                    "family_name": None,
                    "birthdate": None
                }
            }
        }
    }

    _claims_request = IDAClaimsRequest(**_request)

    assert "userinfo" in _claims_request
    assert isinstance(_claims_request["userinfo"], UserInfoClaimsRequest)
    assert "verified_claims" in _claims_request["userinfo"]
    assert isinstance(_claims_request["userinfo"]["verified_claims"], list)
    assert isinstance(_claims_request["userinfo"]["verified_claims"][0], VerifiedClaimsRequest)
    assert "verification" in _claims_request["userinfo"]["verified_claims"][0]
    assert isinstance(_claims_request["userinfo"]["verified_claims"][0]["verification"],
                      VerificationRequest)

    _verified_claims = _claims_request["userinfo"]["verified_claims"][0]
    assert set(_verified_claims["verification"].keys()) == {"trust_framework", "time", "evidence"}
    assert isinstance(_verified_claims["verification"]["evidence"], list)
    assert _verified_claims["verification"]["evidence"][0]["type"] == {"value": "id_document"}


def test_request_verification_evidence_document():
    _request = {
        "userinfo": {
            "verified_claims": {
                "verification": {
                    "trust_framework": None,
                    "time": None,
                    "evidence": [
                        {
                            "type": {
                                "value": "id_document"
                            },
                            "method": None,
                            "document": {
                                "type": None,
                                "issuer": {
                                    "country": None,
                                    "name": None
                                },
                                "number": None,
                                "date_of_issuance": None
                            }
                        }
                    ]
                },
                "claims": {
                    "given_name": None,
                    "family_name": None,
                    "birthdate": None
                }
            }
        }
    }

    _claims_request = IDAClaimsRequest(**_request)

    assert "userinfo" in _claims_request
    assert isinstance(_claims_request["userinfo"], UserInfoClaimsRequest)
    assert "verified_claims" in _claims_request["userinfo"]
    assert isinstance(_claims_request["userinfo"]["verified_claims"], list)
    assert isinstance(_claims_request["userinfo"]["verified_claims"][0], VerifiedClaimsRequest)
    assert "verification" in _claims_request["userinfo"]["verified_claims"][0]
    assert isinstance(_claims_request["userinfo"]["verified_claims"][0]["verification"],
                      VerificationRequest)

    _verified_claims = _claims_request["userinfo"]["verified_claims"][0]
    assert set(_verified_claims["verification"].keys()) == {"trust_framework", "time", "evidence"}
    assert isinstance(_verified_claims["verification"]["evidence"], list)
    assert _verified_claims["verification"]["evidence"][0]["type"] == {"value": "id_document"}
    assert set(_verified_claims["verification"]["evidence"][0]["document"].keys()) == {
        "type", "issuer", "number", "date_of_issuance"
    }
    assert _verified_claims["verification"]["evidence"][0]["document"]["type"] is None


def test_request_verification_values():
    _request = {
        "userinfo": {
            "verified_claims": {
                "verification": {
                    "trust_framework": {
                        "values": [
                            "silver",
                            "bronze"
                        ]
                    }
                },
                "claims": {
                    "given_name": None,
                    "family_name": None
                }
            }
        }
    }

    _claims_request = IDAClaimsRequest(**_request)

    assert "userinfo" in _claims_request
    assert isinstance(_claims_request["userinfo"], UserInfoClaimsRequest)
    assert "verified_claims" in _claims_request["userinfo"]
    assert isinstance(_claims_request["userinfo"]["verified_claims"], list)
    assert isinstance(_claims_request["userinfo"]["verified_claims"][0], VerifiedClaimsRequest)
    assert "verification" in _claims_request["userinfo"]["verified_claims"][0]
    assert isinstance(_claims_request["userinfo"]["verified_claims"][0]["verification"],
                      VerificationRequest)

    _verified_claims = _claims_request["userinfo"]["verified_claims"][0]
    assert set(_verified_claims["verification"].keys()) == {"trust_framework"}
    assert _verified_claims["verification"]["trust_framework"] == {"values": ["silver",
                                                                              "bronze"]}


def test_request_verification_evidence_method():
    _request = {
        "userinfo": {
            "verified_claims": {
                "verification": {
                    "trust_framework": {
                        "value": "de_aml"
                    },
                    "evidence": [
                        {
                            "type": {
                                "value": "id_document"
                            },
                            "method": {
                                "value": "pipp"
                            },
                            "document": {
                                "type": {
                                    "values": [
                                        "idcard",
                                        "passport"
                                    ]
                                }
                            }
                        }
                    ]
                },
                "claims": {
                    "given_name": None,
                    "family_name": None,
                    "birthdate": None
                }
            }
        }
    }

    _claims_request = IDAClaimsRequest(**_request)

    assert "userinfo" in _claims_request
    assert isinstance(_claims_request["userinfo"], UserInfoClaimsRequest)
    assert "verified_claims" in _claims_request["userinfo"]
    assert isinstance(_claims_request["userinfo"]["verified_claims"], list)
    assert isinstance(_claims_request["userinfo"]["verified_claims"][0], VerifiedClaimsRequest)
    assert "verification" in _claims_request["userinfo"]["verified_claims"][0]
    assert isinstance(_claims_request["userinfo"]["verified_claims"][0]["verification"],
                      VerificationRequest)

    _verified_claims = _claims_request["userinfo"]["verified_claims"][0]
    assert set(_verified_claims["verification"].keys()) == {"trust_framework", "evidence"}
    assert set(_verified_claims["verification"]["evidence"][0].keys()) == {"type", "method",
                                                                           "document"}
    assert _verified_claims["verification"]["evidence"][0]["method"] == {"value": "pipp"}


def test_request_verification_max_age():
    _request = {
        "userinfo": {
            "verified_claims": {
                "verification": {
                    "trust_framework": {
                        "value": "jp_aml"
                    },
                    "time": {
                        "max_age": 63113852
                    }
                },
                "claims": {
                    "given_name": None,
                    "family_name": None,
                    "birthdate": None
                }
            }
        }
    }

    _claims_request = IDAClaimsRequest(**_request)

    assert "userinfo" in _claims_request
    assert isinstance(_claims_request["userinfo"], UserInfoClaimsRequest)
    assert "verified_claims" in _claims_request["userinfo"]
    assert isinstance(_claims_request["userinfo"]["verified_claims"], list)
    assert isinstance(_claims_request["userinfo"]["verified_claims"][0], VerifiedClaimsRequest)
    assert "verification" in _claims_request["userinfo"]["verified_claims"][0]
    assert isinstance(_claims_request["userinfo"]["verified_claims"][0]["verification"],
                      VerificationRequest)

    _verification = _claims_request["userinfo"]["verified_claims"][0]["verification"]
    assert _verification["time"]["max_age"] == 63113852


def test_request_multiple_verified_claims():
    _request = {
        "userinfo": {
            "verified_claims": [
                {
                    "verification": {
                        "trust_framework": {
                            "value": "eidas_ial_substantial"
                        }
                    },
                    "claims": {
                        "given_name": None,
                        "family_name": None
                    }
                },
                {
                    "verification": {
                        "trust_framework": {
                            "values": ["eidas_ial_high", "eidas_ial_substantial"]
                        }
                    },
                    "claims": {
                        "birthdate": None
                    }
                }
            ]
        }
    }

    _claims_request = IDAClaimsRequest(**_request)

    assert "userinfo" in _claims_request
    assert isinstance(_claims_request["userinfo"], UserInfoClaimsRequest)
    assert "verified_claims" in _claims_request["userinfo"]
    assert isinstance(_claims_request["userinfo"]["verified_claims"], list)
    assert isinstance(_claims_request["userinfo"]["verified_claims"][0], VerifiedClaimsRequest)
    assert "verification" in _claims_request["userinfo"]["verified_claims"][0]
    assert "verification" in _claims_request["userinfo"]["verified_claims"][1]
    assert isinstance(_claims_request["userinfo"]["verified_claims"][0]["verification"],
                      VerificationRequest)
    assert isinstance(_claims_request["userinfo"]["verified_claims"][1]["verification"],
                      VerificationRequest)

    _trust_frameworks = []
    for vcr in _claims_request["userinfo"]["verified_claims"]:
        _framework = vcr["verification"]["trust_framework"].get("value")
        if not _framework:
            _framework = vcr["verification"]["trust_framework"].get("values")
        _trust_frameworks.append(_framework)

    assert len(_trust_frameworks) == 2
    assert "eidas_ial_substantial" in _trust_frameworks
    assert ["eidas_ial_high", "eidas_ial_substantial"] in _trust_frameworks


def test_request_multiple_verified_claims_2():
    _request = {
        "userinfo": {
            "verified_claims": [
                {
                    "verification": {
                        "trust_framework": {
                            "value": "gold"
                        },
                        "evidence": [
                            {
                                "type": {
                                    "value": "id_document"
                                }
                            }
                        ]
                    },
                    "claims": {
                        "given_name": None,
                        "family_name": None
                    }
                },
                {
                    "verification": {
                        "trust_framework": {
                            "values": ["silver", "bronze"]
                        },
                        "evidence": [
                            {
                                "type": {
                                    "value": "utility_bill"
                                }
                            }
                        ]
                    },
                    "claims": {
                        "given_name": None,
                        "family_name": None
                    }
                }
            ]
        }
    }

    _claims_request = IDAClaimsRequest(**_request)

    assert "userinfo" in _claims_request
    assert isinstance(_claims_request["userinfo"], UserInfoClaimsRequest)
    assert "verified_claims" in _claims_request["userinfo"]
    assert isinstance(_claims_request["userinfo"]["verified_claims"], list)
    assert isinstance(_claims_request["userinfo"]["verified_claims"][0], VerifiedClaimsRequest)
    assert "verification" in _claims_request["userinfo"]["verified_claims"][0]
    assert "verification" in _claims_request["userinfo"]["verified_claims"][1]
    assert isinstance(_claims_request["userinfo"]["verified_claims"][0]["verification"],
                      VerificationRequest)
    assert isinstance(_claims_request["userinfo"]["verified_claims"][1]["verification"],
                      VerificationRequest)

    _trust_frameworks = []
    for vcr in _claims_request["userinfo"]["verified_claims"]:
        _framework = vcr["verification"]["trust_framework"].get("value")
        if not _framework:
            _framework = vcr["verification"]["trust_framework"].get("values")
        _trust_frameworks.append(_framework)

    assert len(_trust_frameworks) == 2
    assert "gold" in _trust_frameworks
    assert ["silver", "bronze"] in _trust_frameworks


def test_id_document():
    _claims = {
        "verified_claims": {
            "verification": {
                "trust_framework": "de_aml",
                "time": "2012-04-23T18:25Z",
                "verification_process": "f24c6f-6d3f-4ec5-973e-b0d8506f3bc7",
                "evidence": [
                    {
                        "type": "id_document",
                        "method": "pipp",
                        "time": "2012-04-22T11:30Z",
                        "document": {
                            "type": "idcard",
                            "issuer": {
                                "name": "Stadt Augsburg",
                                "country": "DE"
                            },
                            "number": "53554554",
                            "date_of_issuance": "2010-03-23",
                            "date_of_expiry": "2020-03-22"
                        }
                    }
                ]
            },
            "claims": {
                "given_name": "Max",
                "family_name": "Meier",
                "birthdate": "1956-01-28",
                "place_of_birth": {
                    "country": "DE",
                    "locality": "Musterstadt"
                },
                "nationalities": [
                    "DE"
                ],
                "address": {
                    "locality": "Maxstadt",
                    "postal_code": "12344",
                    "country": "DE",
                    "street_address": "An der Sandd&#252;ne 22"
                }
            }
        }
    }
    vc = VerifiedClaims(**_claims["verified_claims"])
    vc.verify()
    assert isinstance(vc, VerifiedClaims)
    assert set(vc.keys()) == {'verification', 'claims'}
    assert set(vc['claims'].keys()) == {'address',
                                        'birthdate',
                                        'family_name',
                                        'given_name',
                                        'nationalities',
                                        'place_of_birth'}
    assert set(vc["verification"].keys()) == {'time', 'trust_framework', 'evidence',
                                              'verification_process'}


def test_id_document_and_utility_bill():
    _claims = {
        "verified_claims": {
            "verification": {
                "trust_framework": "de_aml",
                "time": "2012-04-23T18:25Z",
                "verification_process": "513645-e44b-4951-942c-7091cf7d891d",
                "evidence": [
                    {
                        "type": "id_document",
                        "method": "pipp",
                        "time": "2012-04-22T11:30Z",
                        "document": {
                            "type": "de_erp_replacement_idcard",
                            "issuer": {
                                "name": "Stadt Augsburg",
                                "country": "DE"
                            },
                            "number": "53554554",
                            "date_of_issuance": "2010-04-23",
                            "date_of_expiry": "2020-04-22"
                        }
                    },
                    {
                        "type": "utility_bill",
                        "provider": {
                            "name": "Stadtwerke Musterstadt",
                            "country": "DE",
                            "region": "Thüringen",
                            "street_address": "Energiestrasse 33"
                        },
                        "date": "2013-01-31"
                    }
                ]
            },
            "claims": {
                "given_name": "Max",
                "family_name": "Meier",
                "birthdate": "1956-01-28",
                "place_of_birth": {
                    "country": "DE",
                    "locality": "Musterstadt"
                },
                "nationalities": [
                    "DE"
                ],
                "address": {
                    "locality": "Maxstadt",
                    "postal_code": "12344",
                    "country": "DE",
                    "street_address": "An der Sanddüne 22"
                }
            }
        }
    }
    vc = VerifiedClaims(**_claims["verified_claims"])
    vc.verify()
    assert isinstance(vc, VerifiedClaims)
    assert set(vc.keys()) == {'verification', 'claims'}
    assert set(vc['claims'].keys()) == {'address',
                                        'birthdate',
                                        'family_name',
                                        'given_name',
                                        'nationalities',
                                        'place_of_birth'}
    assert set(vc["verification"].keys()) == {'time', 'trust_framework', 'evidence',
                                              'verification_process'}
    assert len(vc["verification"]["evidence"]) == 2
    _types = [e["type"] for e in vc["verification"]["evidence"]]
    assert _types == ['id_document', 'utility_bill']
    for e in vc["verification"]["evidence"]:
        assert isinstance(e, EVIDENCE_TYPE_TO_CLASS[e["type"]])


def test_verified_claims_as_aggregated_claims():
    base_claim = {
        "iss": "https://server.example.com",
        "sub": "248289761001",
        "email": "janedoe@example.com",
        "email_verified": True
    }

    ver_claims = {
        "sub": "e8148603-8934-4245-825b-c108b8b6b945",
        "verified_claims": {
            "verification": {
                "trust_framework": "ial_example_gold"
            },
            "claims": {
                "given_name": "Max",
                "family_name": "Meier",
                "birthdate": "1956-01-28"
            }
        }
    }

    _jwt = JWT(key_jar=KEYS, iss="https://server.otherop.com")
    _jws = _jwt.pack(payload=ver_claims)
    _claims = add_aggregated_claims(base_claim, ["verified_claims"], jwt=_jws)

    _claims_set = aggregated_claim_set(_claims, "src1", KEYS)
    assert "verified_claims" in _claims_set
    assert _claims_set["sub"] == "248289761001"


def test_construct_5_2_1():
    _verification = ClaimsConstructor(Verification)
    _verification["time"] = None
    _verification["evidence"] = None

    verified_claims = ClaimsConstructor("oidcmsg.oidc.identity_assurance.VerifiedClaims")
    verified_claims["verification"] = _verification
    verified_claims["claims"] = None

    _val = verified_claims.to_json()
    assert _val == '{"verification": {"time": null, "evidence": null}, "claims": null}'


def test_request_against_response():
    _request = {
        "userinfo": {
            "verified_claims": [
                {
                    "verification": {
                        "trust_framework": {
                            "value": "de_aml"
                        },
                        "evidence": [
                            {
                                "type": {
                                    "value": "id_document"
                                }
                            }
                        ]
                    },
                    "claims": {
                        "given_name": None,
                        "family_name": None
                    }
                },
                {
                    "verification": {
                        "trust_framework": {
                            "values": ["silver", "bronze"]
                        },
                        "evidence": [
                            {
                                "type": {
                                    "value": "utility_bill"
                                }
                            }
                        ]
                    },
                    "claims": {
                        "given_name": None,
                        "family_name": None,
                        "place_of_birth": None
                    }
                }
            ]
        }
    }

    _claims_request = IDAClaimsRequest(**_request)

    _response = {
        "verified_claims": {
            "verification": {
                "trust_framework": "de_aml",
                "time": "2012-04-23T18:25Z",
                "verification_process": "513645-e44b-4951-942c-7091cf7d891d",
                "evidence": [
                    {
                        "type": "id_document",
                        "method": "pipp",
                        "time": "2012-04-22T11:30Z",
                        "document": {
                            "type": "de_erp_replacement_idcard",
                            "issuer": {
                                "name": "Stadt Augsburg",
                                "country": "DE"
                            },
                            "number": "53554554",
                            "date_of_issuance": "2010-04-23",
                            "date_of_expiry": "2020-04-22"
                        }
                    },
                    {
                        "type": "utility_bill",
                        "provider": {
                            "name": "Stadtwerke Musterstadt",
                            "country": "DE",
                            "region": "Thüringen",
                            "street_address": "Energiestrasse 33"
                        },
                        "date": "2013-01-31"
                    }
                ]
            },
            "claims": {
                "given_name": "Max",
                "family_name": "Meier",
                "birthdate": "1956-01-28",
                "place_of_birth": {
                    "country": "DE",
                    "locality": "Musterstadt"
                },
                "nationalities": [
                    "DE"
                ],
                "address": {
                    "locality": "Maxstadt",
                    "postal_code": "12344",
                    "country": "DE",
                    "street_address": "An der Sanddüne 22"
                }
            }
        }
    }
    vc = VerifiedClaims(**_response["verified_claims"])

    res = match_verified_claims(vc, _claims_request["userinfo"]["verified_claims"])
    assert res
    assert len(res) == 2
    claims = verification_per_claim(res)
    assert len(claims) == 2
    assert set(claims.keys()) == {"given_name", "family_name"}

    # Not de_aml but silver
    vc["verification"]["trust_framework"] = "silver"

    res = match_verified_claims(vc, _claims_request["userinfo"]["verified_claims"])
    assert res
    assert len(res) == 2
    claims = verification_per_claim(res)
    assert len(claims) == 3
    assert set(claims.keys()) == {"given_name", "family_name", "place_of_birth"}


def test_request_response_verification_evidence_method():
    _request = {
        "userinfo": {
            "verified_claims": {
                "verification": {
                    "trust_framework": {
                        "value": "de_aml"
                    },
                    "evidence": [
                        {
                            "type": {
                                "value": "id_document"
                            },
                            "method": {
                                "value": "pipp"
                            },
                            "document": {
                                "type": {
                                    "values": [
                                        "idcard",
                                        "passport"
                                    ]
                                }
                            }
                        }
                    ]
                },
                "claims": {
                    "given_name": None,
                    "family_name": None,
                    "birthdate": None
                }
            }
        }
    }

    _claims_request = IDAClaimsRequest(**_request)

    _response = {
        "verified_claims": {
            "verification": {
                "trust_framework": "de_aml",
                "time": "2012-04-23T18:25Z",
                "verification_process": "513645-e44b-4951-942c-7091cf7d891d",
                "evidence": [
                    {
                        "type": "id_document",
                        "method": "pipp",
                        "time": "2012-04-22T11:30Z",
                        "document": {
                            "type": "passport",
                            "issuer": {
                                "name": "Stadt Augsburg",
                                "country": "DE"
                            },
                            "number": "53554554",
                            "date_of_issuance": "2010-04-23",
                            "date_of_expiry": "2020-04-22"
                        }
                    },
                    {
                        "type": "utility_bill",
                        "provider": {
                            "name": "Stadtwerke Musterstadt",
                            "country": "DE",
                            "region": "Thüringen",
                            "street_address": "Energiestrasse 33"
                        },
                        "date": "2013-01-31"
                    }
                ]
            },
            "claims": {
                "given_name": "Max",
                "family_name": "Meier",
                "birthdate": "1956-01-28",
                "place_of_birth": {
                    "country": "DE",
                    "locality": "Musterstadt"
                },
                "nationalities": [
                    "DE"
                ],
                "address": {
                    "locality": "Maxstadt",
                    "postal_code": "12344",
                    "country": "DE",
                    "street_address": "An der Sanddüne 22"
                }
            }
        }
    }
    vc = VerifiedClaims(**_response["verified_claims"])
