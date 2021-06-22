import abc
import datetime
import json
from typing import Optional
from typing import Union

from cryptojwt.utils import importer

from oidcmsg.exception import MissingRequiredAttribute
from oidcmsg.exception import Unknown
from oidcmsg.message import Message
from oidcmsg.message import OPTIONAL_LIST_OF_STRINGS
from oidcmsg.message import REQUIRED_LIST_OF_STRINGS
from oidcmsg.message import SINGLE_OPTIONAL_JSON
from oidcmsg.message import SINGLE_OPTIONAL_STRING
from oidcmsg.message import SINGLE_REQUIRED_BOOLEAN
from oidcmsg.message import SINGLE_REQUIRED_STRING
from oidcmsg.message import msg_deser
from oidcmsg.message import msg_list_ser
from oidcmsg.message import msg_ser
from oidcmsg.oauth2 import error_chars
from oidcmsg.oidc import AddressClaim
from oidcmsg.oidc import ClaimsRequest
from oidcmsg.oidc import OpenIDSchema
from oidcmsg.oidc import ProviderConfigurationResponse
from oidcmsg.oidc import claims_request_deser
from oidcmsg.oidc import deserialize_from_one_of
from oidcmsg.oidc import msg_ser_json


class PlaceOfBirth(Message):
    c_param = {
        "country": SINGLE_OPTIONAL_STRING,
        "region": SINGLE_OPTIONAL_STRING,
        "locality": SINGLE_OPTIONAL_STRING,
    }


def place_of_birth_deser(val, sformat="json"):
    return deserialize_from_one_of(val, PlaceOfBirth, sformat)


SINGLE_OPTIONAL_PLACE_OF_BIRTH = (PlaceOfBirth,
                                  False,
                                  msg_ser_json,
                                  place_of_birth_deser,
                                  False)

# YYYY-MM-DDThh:mm:ss±hh
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S%z"
DATE_FORMAT = "%Y-%m-%d"


def to_iso8601_2004(val=0, format=TIME_FORMAT):
    """
    :param val: integer/float/datetime.datetime
    :return: A string following the DATE_FORMAT format
    """

    # Finds the local time zone
    ltz = datetime.datetime.utcnow().astimezone().tzinfo

    if val:
        if isinstance(val, datetime.datetime):
            d = val
        elif isinstance(val, (int, float)):
            d = datetime.datetime.fromtimestamp(val)
        else:
            raise ValueError("Unsupported value type")
    else:
        d = datetime.datetime.now()

    return d.replace(tzinfo=ltz).strftime(format)


def from_iso8601_2004(isotime, format=TIME_FORMAT):
    """
    :param isotime: A string following the DATE_FORMAT format
    :return: A time stamp (int)
    """
    d = datetime.datetime.strptime(isotime, format)
    return d.timestamp()


def to_iso8601_2004_time(val=0):
    return to_iso8601_2004(val, format=TIME_FORMAT)


def to_iso8601_2004_date(val=0):
    return to_iso8601_2004(val, format=DATE_FORMAT)


def from_iso8601_2004_time(val):
    return from_iso8601_2004(val, format=TIME_FORMAT)


def from_iso8601_2004_date(val):
    return from_iso8601_2004(val, format=DATE_FORMAT)


def time_stamp_ser(val, sformat="", lev=0):
    """
    Convert from seconds since epoch to ISO 8601:2004 [ISO8601-2004] YYYY-MM-DDThh:mm:ss±hh format.
    """
    if isinstance(val, int):
        return to_iso8601_2004_time(val)
    elif isinstance(val, float):
        return to_iso8601_2004_time(int(val))
    elif isinstance(val, str):
        return to_iso8601_2004_time(int(val))
    else:
        raise ValueError("Wrong type of value")


def time_stamp_deser(val, sformat="", lev=0):
    if isinstance(val, (int, float)):
        return val
    else:  # A string following the
        return from_iso8601_2004_time(val)


REQURIED_TIME_STAMP = (str, True, time_stamp_ser, time_stamp_deser, False)
OPTIONAL_TIME_STAMP = (str, False, time_stamp_ser, time_stamp_deser, False)


def date_ser(val, sformat="", lev=0):
    """
    Convert from seconds since epoch to ISO 8601:2004 [ISO8601-2004] YYYY-MM-DDThh:mm:ss±hh format.
    """
    if isinstance(val, int):
        return to_iso8601_2004_date(val)
    elif isinstance(val, float):
        return to_iso8601_2004_date(int(val))
    elif isinstance(val, str):
        return to_iso8601_2004_date(int(val))
    else:
        raise ValueError("Wrong type of value")


def date_deser(val, sformat="", lev=0):
    if isinstance(val, (int, float)):
        return val
    else:  # A string following the
        return from_iso8601_2004_date(val)


REQURIED_DATE = (str, True, date_ser, date_deser, False)
OPTIONAL_DATE = (str, False, date_ser, date_deser, False)


class IdentityAssuranceClaims(OpenIDSchema):
    c_param = OpenIDSchema.c_param.copy()
    c_param.update(
        {
            "place_of_birth": SINGLE_OPTIONAL_JSON,
            "nationalities": SINGLE_OPTIONAL_STRING,
            "birth_family_name": SINGLE_OPTIONAL_STRING,
            "birth_given_name": SINGLE_OPTIONAL_STRING,
            "birth_middle_name": SINGLE_OPTIONAL_STRING,
            "salutation": SINGLE_OPTIONAL_STRING,
            "title": SINGLE_OPTIONAL_STRING,
        }
    )


def identity_assurance_claims_deser(val, sformat="json"):
    return deserialize_from_one_of(val, IdentityAssuranceClaims, sformat)


OPTIONAL_IDA_CLAIMS = (IdentityAssuranceClaims, False, msg_ser,
                       identity_assurance_claims_deser, False)


class Verifier(Message):
    c_param = {"organization": SINGLE_REQUIRED_STRING, "txn": SINGLE_REQUIRED_STRING}


def verifier_claims_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, Verifier, sformat)


REQUIRED_VERIFIER = (Verifier, True, msg_ser, verifier_claims_deser, False)


class Issuer(Message):
    c_param = {"name": SINGLE_REQUIRED_STRING, "country": SINGLE_REQUIRED_STRING}


def issuer_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, Issuer, sformat)


REQUIRED_ISSUER = (Issuer, True, msg_ser, issuer_deser, False)


class Document(Message):
    c_param = {
        "type": SINGLE_REQUIRED_STRING,
        "number": SINGLE_REQUIRED_STRING,
        "issuer": REQUIRED_ISSUER,
        "date_of_issuance": REQURIED_TIME_STAMP,
        "date_of_expiry": REQURIED_TIME_STAMP,
    }


def document_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, Document, sformat)


OPTIONAL_DOCUMENT = (Document, False, msg_ser, document_deser, False)


class Evidence(Message):
    c_param = {"type": SINGLE_REQUIRED_STRING}


def evidence_deser(val, sformat="json"):
    if sformat in ["dict", "json"]:
        if isinstance(val, str):
            val = json.loads(val)

    return _map_evidence_type_to_class(val)


def evidence_list_deser(val, sformat="urlencoded", lev=0):
    if isinstance(val, dict):
        return [_map_evidence_type_to_class(val)]

    _res = [evidence_deser(v, sformat) for v in val]
    return _res


OPTIONAL_EVIDENCE_LIST = ([Evidence], False, msg_list_ser, evidence_list_deser, True)


def message_deser(val, msgtype, sformat="urlencoded"):
    if isinstance(val, Message):
        return val
    elif sformat in ["dict", "json"]:
        if not isinstance(val, str):
            val = json.dumps(val)
            sformat = "json"
    return msgtype().deserialize(val, sformat)


class IdDocument(Evidence):
    c_param = Evidence.c_param.copy()
    c_param.update(
        {
            "method": SINGLE_REQUIRED_STRING,
            "verifier": REQUIRED_VERIFIER,
            "time": OPTIONAL_TIME_STAMP,
            "document": OPTIONAL_DOCUMENT,
        }
    )


def id_document_deser(val, sformat="urlencoded"):
    return message_deser(val, IdDocument, sformat)


REQUIRED_ID_DOCUMENT = (IdDocument, True, msg_ser, id_document_deser, False)
OPTIONAL_ID_DOCUMENT = (IdDocument, False, msg_ser, id_document_deser, False)


class Provider(AddressClaim):
    c_param = AddressClaim.c_param.copy()
    c_param.update(
        {
            "name": SINGLE_OPTIONAL_STRING,
        }
    )


def provider_deser(val, sformat="urlencoded"):
    return message_deser(val, Provider, sformat)


REQUIRED_PROVIDER = (Provider, True, msg_ser, provider_deser, False)


class UtilityBill(Evidence):
    c_param = Evidence.c_param.copy()
    c_param.update({"provider": REQUIRED_PROVIDER, "date": OPTIONAL_TIME_STAMP})


def utility_bill_deser(val, sformat="urlencoded"):
    return message_deser(val, UtilityBill, sformat)


REQUIRED_UTILITY_BILL = (UtilityBill, True, msg_ser, utility_bill_deser, False)
OPTIONAL_UTILITY_BILL = (UtilityBill, False, msg_ser, utility_bill_deser, False)


class QES(Evidence):
    c_param = Evidence.c_param.copy()
    c_param.update(
        {
            "issuer": SINGLE_REQUIRED_STRING,
            "serial_number": SINGLE_REQUIRED_STRING,
            "created_at": REQURIED_TIME_STAMP,
        }
    )


def qes_deser(val, sformat="urlencoded"):
    return message_deser(val, QES, sformat)


REQUIRED_QES = (QES, True, msg_ser, qes_deser, False)
OPTIONAL_QES = (QES, False, msg_ser, qes_deser, False)


def address_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, AddressClaim, sformat)


OPTIONAL_ADDRESS = (AddressClaim, False, msg_ser, address_deser, False)

EVIDENCE_TYPE_TO_CLASS = {
    "id_document": IdDocument,
    "utility_bill": UtilityBill,
    "qes": QES
}


def _map_evidence_type_to_class(val):
    _type = val.get("type")
    if _type:
        try:
            item = EVIDENCE_TYPE_TO_CLASS[_type](**val)
        except KeyError:
            raise Unknown(f"Evidence type: {_type}")
    else:
        raise MissingRequiredAttribute("type")

    return item


class Verification(Message):
    c_param = {
        "trust_framework": SINGLE_REQUIRED_STRING,
        "time": OPTIONAL_TIME_STAMP,
        "verification_process": SINGLE_OPTIONAL_STRING,
        "evidence": OPTIONAL_EVIDENCE_LIST,
    }


def verification_deser(val, sformat="urlencoded"):
    return message_deser(val, Verification, sformat)


OPTIONAL_VERIFICATION = (
    Verification,
    False,
    msg_ser,
    verification_deser,
    False,
)

REQUIRED_VERIFICATION = (
    Verification,
    True,
    msg_ser,
    verification_deser,
    False,
)


class VerifiedClaims(Message):
    c_param = {
        "verification": REQUIRED_VERIFICATION,
        "claims": REQUIRED_VERIFICATION}


#
# ===================== CLAIMS REQUESTS =====================
#

SINGLE_OPTIONAL_CLAIMSREQ = (ClaimsRequest, False, msg_ser_json, claims_request_deser, False)


def _correct_value_type(val, value_type):
    if isinstance(value_type, Message):
        pass
    else:
        if not isinstance(val, value_type):  # the simple case
            return False
    return True


def _verify_claims_request_value(value, value_type=str):
    if value is None:
        return True
    elif isinstance(value, dict):
        # know about keys: essential, value and values, purpose
        if not value.get("essential") in (None, True, False):
            return False

        _v = value.get("value")
        if _v:
            if not _correct_value_type(_v, value_type):
                return False

        _vs = value.get("values", [])
        for _v in _vs:
            if not _correct_value_type(_v, value_type):
                return False

        _p = value.get("purpose")
        if _p:
            if len(_p) < 3 or len(_p) > 300:
                return False
            if not all(x in error_chars for x in _p):
                return False

    return True


def verify_claims_request(instance, base_cls_instance):
    # Verify that the claims request is correctly specified
    for key, spec in base_cls_instance.c_param.items():
        try:
            _val = instance[key]
        except KeyError:
            continue

        _value_type = spec[0]

        if _value_type in (str, int, bool):
            if not _verify_claims_request_value(_val, _value_type):
                raise ValueError("{}: '{}'".format(key, _val))
        elif type(_value_type) == abc.ABCMeta:
            if _val is None:
                continue
            verify_claims_request(_val, _value_type())
        elif isinstance(_value_type, list):
            if _val is None:
                continue
            _item_val_type = _value_type[0]
            for _v in _val:
                if _item_val_type in (str, int, bool):
                    if not _verify_claims_request_value(_v, _item_val_type):
                        raise ValueError("{}: '{}'".format(key, _v))
                elif type(_item_val_type) == abc.ABCMeta:
                    if _v is None:
                        continue
                    verify_claims_request(_v, _item_val_type())


class IdentityAssuranceClaimsRequest(Message):
    base_class = Message

    def verify(self, **kwargs):
        super(IdentityAssuranceClaimsRequest, self).verify(**kwargs)
        # Verify that the claims request is correctly specified
        for key, spec in self.base_class.c_param.items():
            try:
                _val = self[key]
            except KeyError:
                continue

            _value_type = spec[0]

            if _value_type in (str, int, bool):
                if not _verify_claims_request_value(_val, _value_type):
                    raise ValueError("{}: '{}'".format(key, _val))
            elif type(_value_type) == abc.ABCMeta:
                if _val is None:
                    continue
                verify_claims_request(_val, _value_type())
            elif isinstance(_value_type, list):
                if _val is None:
                    continue
                _item_val_type = _value_type[0]
                for _v in _val:
                    if _item_val_type in (str, int, bool):
                        if not _verify_claims_request_value(_v, _item_val_type):
                            raise ValueError("{}: '{}'".format(key, _v))
                    elif type(_item_val_type) == abc.ABCMeta:
                        if _v is None:
                            continue
                        verify_claims_request(_v, _item_val_type())

    # def _item_match(self, item, response_claims, attr):
    #     matched = {}
    #     if isinstance(item, IdentityAssuranceClaimsRequest):
    #         _m = item.match_against_response(response_claims.get(attr))
    #         if _m:
    #             matched.update(_m)
    #     else:
    #         _m = claims_match(item, response_claims.get(attr))
    #         if _m:
    #             matched.update(_m)
    #     return matched
    #
    # def match_response(self, claims):
    #     for attr, req in self.items():
    #         if attr in self.c_param:
    #             continue
    #         if claims_match(claims.get(attr), req) is False:
    #             return None
    #     return copy.deepcopy(claims)
    #
    # def match_against_response(self, response_claims):
    #     matched = {}
    #     for attr in list(self.c_param.keys()):
    #         _item = self.get(attr)
    #         if _item:
    #             if isinstance(_item, list):
    #                 for _i in _item:
    #                     _m = self._item_match(_i, response_claims, attr)
    #                     if _m:
    #                         try:
    #                             matched[attr].append(_m)
    #                         except KeyError:
    #                             matched[attr] = [_m]
    #             else:
    #                 _m = self._item_match(_item, response_claims, attr)
    #                 if _m:
    #                     matched[attr] = [_m]
    #
    #     if isinstance(response_claims, list):
    #         for resp in response_claims:
    #             _m = self.match_response(resp)
    #             if _m:
    #                 try:
    #                     matched.update(_m)
    #                 except KeyError:
    #                     matched[_key] = [_m]
    #     else:
    #         _key = self.base_class.__name__
    #         _m = self.match_response(response_claims)
    #         if _m:
    #             matched[_key] = _m
    #
    #     return matched


OPTIONAL_CLAIMS_REQUEST = (IdentityAssuranceClaimsRequest, False, msg_ser, msg_deser, True)


def evidence_request_deser(val, sformat="json"):
    if sformat in ["dict", "json"]:
        if isinstance(val, str):
            val = json.loads(val)

    return EvidenceRequest(**val)


def evidence_list_deser(val, sformat="urlencoded", lev=0):
    if isinstance(val, dict):
        return [EvidenceRequest(**val)]

    _res = [evidence_request_deser(v, sformat) for v in val]
    return _res


class EvidenceRequest(IdentityAssuranceClaimsRequest):
    base_class = Evidence


OPTIONAL_EVIDENCE_REQUEST_LIST = ([EvidenceRequest], False, msg_list_ser, evidence_list_deser, True)


class VerificationRequest(IdentityAssuranceClaimsRequest):
    base_class = Verification
    c_param = {'evidence': OPTIONAL_EVIDENCE_REQUEST_LIST}
    # c_param = {
    #     "trust_framework": SINGLE_REQUIRED_STRING,
    #     "time": OPTIONAL_TIME_STAMP,
    #     "verification_process": SINGLE_OPTIONAL_STRING,
    #     "evidence": OPTIONAL_EVIDENCE_REQUEST_LIST,
    # }

    # def verify(self, **kwargs):
    #     super(VerificationRequest, self).verify(**kwargs)
    #     if "trust_framework" not in self:
    #         raise MissingRequiredAttribute("trust_framework")


def verification_request_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, VerificationRequest, sformat)


OPTIONAL_VERIFICATION_REQUEST = (
    VerificationRequest,
    False,
    msg_ser,
    verification_request_deser,
    True,
)


class VerifiedClaimsRequest(IdentityAssuranceClaimsRequest):
    c_param = {"verification": OPTIONAL_VERIFICATION_REQUEST,
               "claims": OPTIONAL_CLAIMS_REQUEST}


def verified_claims_request_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, VerifiedClaimsRequest, sformat)


def verified_claims_request_list_deser(val, sformat="urlencoded", lev=0):
    if isinstance(val, dict):
        return [VerifiedClaimsRequest(**val)]

    _res = [verified_claims_request_deser(v, sformat) for v in val]
    return _res


OPTIONAL_LIST_OF_VERIFIED_CLAIMS_REQUEST = (
    [VerifiedClaimsRequest], False, msg_list_ser, verified_claims_request_list_deser, True)


class UserInfoClaimsRequest(IdentityAssuranceClaimsRequest):
    c_param = {"verified_claims": OPTIONAL_LIST_OF_VERIFIED_CLAIMS_REQUEST}


def userinfo_claims_request_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, UserInfoClaimsRequest, sformat)


OPTIONAL_USERINFO_CLAIMS_REQUEST = (
    UserInfoClaimsRequest,
    False,
    msg_ser,
    userinfo_claims_request_deser,
    True,
)


class IdTokenClaimsRequest(IdentityAssuranceClaimsRequest):
    c_param = {"verified_claims": OPTIONAL_LIST_OF_VERIFIED_CLAIMS_REQUEST}


def idtoken_claims_request_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, IdTokenClaimsRequest, sformat)


OPTIONAL_IDTOKEN_CLAIMS_REQUEST = (
    IdTokenClaimsRequest,
    False,
    msg_ser,
    idtoken_claims_request_deser,
    True,
)


class IDAClaimsRequest(IdentityAssuranceClaimsRequest):
    c_param = {"userinfo": OPTIONAL_USERINFO_CLAIMS_REQUEST,
               "id_token": OPTIONAL_IDTOKEN_CLAIMS_REQUEST}


class ClaimsConstructor:
    def __init__(self, base_class=Message):
        if isinstance(base_class, str):
            self.base_class = importer(base_class)()
        elif isinstance(base_class, Message):
            self.base_class = base_class
        elif type(base_class) == abc.ABCMeta:
            self.base_class = base_class()

        self.info = {}

    def __setitem__(self, key: str, value):
        """

        :param key:
        :param value: one of None or a dictionary with keys: "essential",
        "value" or "values.
        :return:
        """
        if value is not None:
            _value_type = self.base_class.value_type(key)
            if _value_type:
                if isinstance(value, ClaimsConstructor):
                    if not isinstance(value.base_class, _value_type):
                        raise ValueError(
                            "Wrong type of value '{}':'{}'".format(key, type(value.base_class))
                        )
                elif not _correct_value_type(value, _value_type):
                    raise ValueError("Wrong type of value '{}':'{}'".format(key, type(value)))

        self.info[key] = value

    def to_dict(self) -> dict:
        res = {}
        for key, val in self.info.items():
            if isinstance(val, ClaimsConstructor):
                res[key] = val.to_dict()
            else:
                res[key] = val
        return res

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


# ----------------------

def claims_match(value: Union[str, int], claimspec: Optional[dict]) -> bool:
    """
    Implements matching according to section 5.5.1 of
    http://openid.net/specs/openid-connect-core-1_0.html
    The lack of value is not checked here.
    Also the text doesn't prohibit having both 'value' and 'values'.

    :param value: single value
    :param claimspec: None or dictionary with 'essential', 'value' or 'values'
        as key
    :return: Boolean
    """
    if value is None:
        return False

    if claimspec is None:  # match anything
        return True

    matched = False
    for key, val in claimspec.items():
        if key == "value":
            if value == val:
                matched = True
        elif key == "values":
            if value in val:
                matched = True
        elif key == "essential":
            # Whether it's essential or not doesn't change anything here
            continue

        if matched:
            break

    if matched is False:
        if list(claimspec.keys()) == ["essential"]:
            return True

    return matched


def match_class_singles(provided, requested, strict=True) -> dict:
    matched = {}
    for key, req_val in requested.items():
        _ver_val = provided.get(key)
        if isinstance(req_val, IdentityAssuranceClaimsRequest):
            matched[key] = match_class_singles(_ver_val, req_val)
        elif claims_match(_ver_val, req_val):
            matched[key] = _ver_val
        else:
            return {}

    if not strict:  # Include those that wasn't asked for
        for key, val in provided.items():
            if key not in requested:
                matched[key] = val

    return matched


def match_class(provided, requested, strict=True) -> Union[dict, bool]:
    matched = {}
    for key, req_val in requested.items():
        _ver_val = provided.get(key)
        if isinstance(req_val, list):
            _matched = []
            for _rval in req_val:
                if isinstance(_ver_val, list):
                    for _vval in _ver_val:
                        _m = match_class(_vval, _rval, strict)
                        if _m:
                            _matched.append(_m)
                else:
                    _m = match_class(_ver_val, _rval, strict)
                    if _m:
                        _matched.append(_m)
            if _matched:
                matched[key] = _matched
        elif isinstance(_ver_val, list):
            _matched = []
            for _vval in _ver_val:
                _m = match_class(_vval, req_val, strict)
                if _m:
                    _matched.append(_m)
            if _matched:
                matched[key] = _matched
        elif isinstance(req_val, IdentityAssuranceClaimsRequest):
            matched[key] = match_class_singles(_ver_val, req_val)
        elif claims_match(_ver_val, req_val):
            matched[key] = _ver_val
        else:
            return False

    if not strict:  # Include those that wasn't asked for
        for key, val in provided.items():
            if key not in requested:
                matched[key] = val

    return matched


def match_claims(claims, claims_request, strict=True) -> dict:
    matched = {}
    for key, req_val in claims_request.items():
        _claims_val = claims.get(key)
        if claims_match(_claims_val, req_val) is False:
            return {}
        matched[key] = _claims_val

    if not strict:  # Include those that wasn't asked for
        for key, val in claims.items():
            if key not in claims_request:
                matched[key] = val

    return matched


def match_single_verified_claims(verified_claims, verified_claims_request):
    matched_verification = match_class(verified_claims.get("verification"),
                                       verified_claims_request.get("verification"),
                                       strict=False)
    if matched_verification:
        matched_claims = match_claims(verified_claims.get("claims"),
                                      verified_claims_request.get("claims"))
    else:
        matched_claims = {}

    return {"verification": matched_verification, "claims": matched_claims}


def match_verified_claims(verified_claims, verified_claims_request) -> list:
    matched = []

    if isinstance(verified_claims, list):
        for _vc in verified_claims:
            if isinstance(verified_claims_request, list):
                for _vcr in verified_claims_request:
                    _match = match_single_verified_claims(_vc, _vcr)
                    if _match:
                        matched.append(_match)
            else:
                _match = match_single_verified_claims(_vc, verified_claims_request)
                if _match:
                    matched.append(_match)
    else:
        if isinstance(verified_claims_request, list):
            for _vcr in verified_claims_request:
                _match = match_single_verified_claims(verified_claims, _vcr)
                if _match:
                    matched.append(_match)
        else:
            _match = match_single_verified_claims(verified_claims, verified_claims_request)
            if _match:
                matched.append(_match)

    return matched


def _hashable(key):
    if isinstance(key, dict):
        return json.dumps(key)

    return key


def verification_per_claim(matched):
    res = {}
    for m in matched:
        for key, val in m['claims'].items():
            _interim = {}
            if isinstance(val, list):
                for v in val:
                    _interim[_hashable(v)] = [m["verification"]]
            else:
                _interim[_hashable(val)] = [m["verification"]]

            if key is res:
                for ikey, val in _interim.items():
                    if ikey in res[key]:
                        res[key][_hashable(ikey)].extend(val)
                    else:
                        res[key][_hashable(ikey)] = val
            else:
                res[key] = _interim

    return res


# ==========================================================================================

class IDAOPMetadata(ProviderConfigurationResponse):
    c_param = ProviderConfigurationResponse.c_param.copy()
    c_param.update({
        "verified_claims_supported": SINGLE_REQUIRED_BOOLEAN,
        "trust_frameworks_supported": REQUIRED_LIST_OF_STRINGS,
        "evidence_supported": REQUIRED_LIST_OF_STRINGS,
        "id_documents_supported": OPTIONAL_LIST_OF_STRINGS,
        "id_documents_verification_methods_supported": OPTIONAL_LIST_OF_STRINGS,
        "claims_in_verified_claims_supported": REQUIRED_LIST_OF_STRINGS
    })
