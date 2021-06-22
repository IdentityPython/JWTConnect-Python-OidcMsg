# Constructs and parses a claim set with distributed and/or aggregated claims
from cryptojwt import JWT
from cryptojwt.jws.jws import factory


def _add_claims(claim_set, claim_names, src_spec):
    # uses src# as source identifier
    _sources = claim_set.get("_claim_sources", {})
    if _sources:
        _srcs = list(_sources.keys())
        _srcs.sort()
        highest_nr = int(_srcs[-1][3:])
        next_nr = highest_nr + 1
    else:
        next_nr = 1

    _new_src = f"src{next_nr}"
    _sources[_new_src] = src_spec
    claim_set["_claim_sources"] = _sources

    _names = claim_set.get("_claim_names", {})
    for _name in claim_names:
        _present = _names.get(_name)
        if _present is None:
            _names[_name] = _new_src
        elif isinstance(_present, list):
            _name[_name].append(_new_src)
        else:
            _name[_name] = [_name[_name], _new_src]
    claim_set["_claim_names"] = _names

    return claim_set


def add_aggregated_claims(claim_set, claim_names, jwt):
    return _add_claims(claim_set, claim_names, {"JWT": jwt})


def add_distributed_claims(claim_set, claim_names, endpoint, access_token=""):
    _src_spec = {"endpoint", endpoint}
    if access_token:
        _src_spec["access_token"] = access_token

    return _add_claims(claim_set, claim_names, _src_spec)


def aggregated_claim_set(claim_set, src, key_jar):
    _srcs = claim_set.get("_claim_sources")
    if _srcs:
        _jwt = _srcs.get(src).get("JWT")
    else:
        raise KeyError("Missing parameter _claim_sources")

    verifier = JWT(key_jar=key_jar)
    _jws = verifier.unpack(_jwt)

    _names = claim_set.get("_claim_names", {})
    for attr, val in _names.items():
        if src == val or src in val:
            _jwt_val = _jws.get(attr)
            if _jwt_val is None:
                continue

            if isinstance(_jwt_val, list):
                try:
                    claim_set[attr].extend(_jwt_val)
                except AttributeError:
                    if isinstance(_jwt_val, list):
                        claim_set[attr] = [claim_set[attr]] + _jwt_val
                    else:
                        claim_set[attr] = [claim_set[attr], _jwt_val]
                except KeyError:
                    claim_set[attr] = _jwt_val
            else:
                try:
                    claim_set[attr].append(_jwt_val)
                except AttributeError:
                    if isinstance(_jwt_val, list):
                        claim_set[attr] = [claim_set[attr]] + _jwt_val
                    else:
                        claim_set[attr] = [claim_set[attr], _jwt_val]
                except KeyError:
                    claim_set[attr] = _jwt_val

    return claim_set