import abc
import datetime
import json

from cryptojwt.utils import importer

from oidcmsg.message import Message
from oidcmsg.message import OPTIONAL_LIST_OF_MESSAGES
from oidcmsg.message import OPTIONAL_LIST_OF_STRINGS
from oidcmsg.message import OPTIONAL_MESSAGE
from oidcmsg.message import SINGLE_OPTIONAL_INT
from oidcmsg.message import SINGLE_OPTIONAL_JSON
from oidcmsg.message import SINGLE_OPTIONAL_STRING
from oidcmsg.message import SINGLE_REQUIRED_STRING
from oidcmsg.message import msg_deser
from oidcmsg.message import msg_list_ser
from oidcmsg.message import msg_ser
from oidcmsg.oauth2 import error_chars
from oidcmsg.oidc import AddressClaim
from oidcmsg.oidc import AddressClaim as address_claim
from oidcmsg.oidc import ClaimsRequest
from oidcmsg.oidc import OpenIDSchema
from oidcmsg.oidc import claims_request_deser
from oidcmsg.oidc import deserialize_from_one_of
from oidcmsg.oidc import msg_ser_json


class PlaceOfBirth(Message):
    c_param = {
        "country": SINGLE_REQUIRED_STRING,
        "region": SINGLE_OPTIONAL_STRING,
        "locality": SINGLE_REQUIRED_STRING,
    }


def place_of_birth_deser(val, sformat="json"):
    # never 'urlencoded'
    if sformat == "urlencoded":
        sformat = "json"

    if sformat == "json":
        if not isinstance(val, str):
            val = json.dumps(val)
            sformat = "json"
    elif sformat == "dict":
        if isinstance(val, str):
            val = json.loads(val)

    return PlaceOfBirth().deserialize(val, sformat)


SINGLE_OPTIONAL_PLACE_OF_BIRTH = (PlaceOfBirth, False, msg_ser_json, place_of_birth_deser, False)

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
            "nationalities": OPTIONAL_LIST_OF_STRINGS,
            "birth_family_name": SINGLE_OPTIONAL_STRING,
            "birth_given_name": SINGLE_OPTIONAL_STRING,
            "birth_middle_name": SINGLE_OPTIONAL_STRING,
            "salutation": SINGLE_OPTIONAL_STRING,
            "title": SINGLE_OPTIONAL_STRING,
            "msisdn": SINGLE_OPTIONAL_STRING,
            "also_known_as": SINGLE_OPTIONAL_STRING,
        }
    )


OPTIONAL_IDA_CLAIMS = (IdentityAssuranceClaims, False, msg_ser, msg_deser, False)


# ------------ Issuer ---------------

class Issuer(Message):
    c_param = {"name": SINGLE_REQUIRED_STRING, "country": SINGLE_REQUIRED_STRING}


def issuer_deser(val, sformat="urlencoded"):
    if isinstance(val, Message):
        return val
    elif sformat in ["dict", "json"]:
        if not isinstance(val, str):
            val = json.dumps(val)
            sformat = "json"
    return Issuer().deserialize(val, sformat)


REQUIRED_ISSUER = (Issuer, True, msg_ser, issuer_deser, False)


# ------------ EmbeddedAttachment ---------------

class EmbeddedAttachment(Message):
    c_param = {
        "desc": SINGLE_OPTIONAL_STRING,
        "content_type": SINGLE_REQUIRED_STRING,
        "content": SINGLE_REQUIRED_STRING
    }


# ------------ Digest -----------------

class Digest(Message):
    c_param = {
        "alg": SINGLE_REQUIRED_STRING,
        "value": SINGLE_REQUIRED_STRING
    }


def digest_deser(val, sformat="json"):
    return deserialize_from_one_of(val, Digest, sformat)


REQUIRED_DIGEST = (Digest, True, msg_ser, digest_deser, False)


# ------------ ExternalAttachment ---------------

class ExternalAttachment(Message):
    c_param = {
        "desc": SINGLE_OPTIONAL_STRING,
        "url": SINGLE_REQUIRED_STRING,
        "access_token": SINGLE_OPTIONAL_STRING,
        "expires_in": SINGLE_OPTIONAL_INT,
        "digest": REQUIRED_DIGEST
    }


# ----------------------------------------

class Evidence(Message):
    c_param = {
        "type": SINGLE_OPTIONAL_STRING,
        "attachments": OPTIONAL_LIST_OF_MESSAGES
    }

    def verify(self, **kwargs):
        _attachment_list = []
        for attachment in self.get("attachments", []):
            for _att_class in [EmbeddedAttachment, ExternalAttachment]:
                _att = _att_class(**attachment)
                try:
                    _att.verify()
                except Exception:
                    pass
                else:
                    _attachment_list.append(_att)
                    break
        if _attachment_list:
            self.set_value("attachments", _attachment_list)


def evidence_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, Evidence, sformat)


def evidence_list_deser(val, sformat="urlencoded", lev=0):
    if isinstance(val, dict):
        return [Message(**val)]

    _res = [evidence_deser(v, sformat) for v in val]
    return _res


OPTIONAL_EVIDENCE_LIST = ([Evidence], False, msg_list_ser, evidence_list_deser, True)


# ------------ ValidationMethod ---------------

class ValidationMethod(Message):
    c_param = {
        "type": SINGLE_REQUIRED_STRING,
        "policy": SINGLE_OPTIONAL_STRING,
        "procedure": SINGLE_OPTIONAL_STRING,
        "status": SINGLE_OPTIONAL_STRING
    }


def validation_method_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, ValidationMethod, sformat)


OPTIONAL_VALIDATION_METHOD = (ValidationMethod, False, msg_ser, validation_method_deser, False)


# ------------ VerificationMethod ---------------

class VerificationMethod(Message):
    c_param = {
        "type": SINGLE_REQUIRED_STRING,
        "policy": SINGLE_OPTIONAL_STRING,
        "procedure": SINGLE_OPTIONAL_STRING,
        "status": SINGLE_OPTIONAL_STRING
    }


def verification_method_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, VerificationMethod, sformat)


OPTIONAL_VERIFICATION_METHOD = (
    VerificationMethod, False, msg_ser, verification_method_deser, False)


# ------------ Verifier ---------------

class Verifier(Message):
    c_param = {
        "organization": SINGLE_REQUIRED_STRING,
        "txn": SINGLE_OPTIONAL_STRING,
    }


def verifier_deser(val, sformat="json"):
    return deserialize_from_one_of(val, Verifier, sformat)


OPTIONAL_VERIFIER = (Verifier, False, msg_ser, verifier_deser, False)
REQUIRED_VERIFIER = (Verifier, True, msg_ser, verifier_deser, False)


# ------------ Source ---------------

class Source(Message):
    c_param = {
        "name": SINGLE_OPTIONAL_STRING,
        "country_code": SINGLE_OPTIONAL_STRING,
        "jurisdiction": SINGLE_OPTIONAL_STRING
    }
    c_param.update(AddressClaim.c_param.copy())


def source_deser(val, sformat="json"):
    return deserialize_from_one_of(val, Source, sformat)


OPTIONAL_SOURCE = (Source, False, msg_ser, source_deser, False)


# ------------ DocumentDetails ---------------

class DocumentDetails(Message):
    c_param = {
        "type": SINGLE_REQUIRED_STRING,
        "document_number": SINGLE_OPTIONAL_STRING,
        "personal_number": SINGLE_OPTIONAL_STRING,
        "serial_number": SINGLE_OPTIONAL_STRING,
        "date_of_issuance": OPTIONAL_DATE,
        "date_of_expiry": OPTIONAL_DATE,
        "issuer": OPTIONAL_SOURCE
    }


def document_details_deser(val, sformat="json"):
    return deserialize_from_one_of(val, DocumentDetails, sformat)


OPTIONAL_DOCUMENT_DETAILS = (DocumentDetails, False, msg_ser, document_details_deser, False)


# ------------ Document ---------------

class Document(Evidence):
    c_param = Evidence.c_param.copy()
    c_param.update({
        "validation_method": OPTIONAL_VALIDATION_METHOD,
        "verification_method": OPTIONAL_VERIFICATION_METHOD,
        "method": SINGLE_OPTIONAL_STRING,
        "verifier": OPTIONAL_VERIFIER,
        "document_details": OPTIONAL_DOCUMENT_DETAILS,
    })


def document_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, Document, sformat)


OPTIONAL_DOCUMENT = (Document, False, msg_ser, document_deser, False)


# ------------ Record ---------------

class Record(Message):
    c_param = {
        "type": SINGLE_REQUIRED_STRING,
        "personal_number": SINGLE_OPTIONAL_STRING,
        "created_at": OPTIONAL_TIME_STAMP,
        "date_of_expiry": OPTIONAL_DATE,
        "source": OPTIONAL_SOURCE
    }


def record_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, Record, sformat)


OPTIONAL_RECORD = (Record, False, msg_ser, record_deser, False)


# ------------ Electronic Record ---------------

class ElectronicRecord(Evidence):
    c_param = Evidence.c_param.copy()
    c_param.update({
        "validation_method": OPTIONAL_VALIDATION_METHOD,
        "verification_method": OPTIONAL_VERIFICATION_METHOD,
        "verifier": OPTIONAL_VERIFIER,
        "time": OPTIONAL_TIME_STAMP,
        "record": OPTIONAL_RECORD,
    })


# ------------- Voucher -----------------

class Voucher(Message):
    c_param = {
        "name": SINGLE_OPTIONAL_STRING,
        "birthdate": SINGLE_OPTIONAL_STRING,
        "occupation": SINGLE_OPTIONAL_STRING,
        "organization": SINGLE_OPTIONAL_STRING
    }
    c_param.update(AddressClaim.c_param.copy())


def voucher_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, Voucher, sformat)


OPTIONAL_VOUCHER = (Voucher, False, msg_ser, voucher_deser, False)


# ------------- Attestation -----------------

class Attestation(Message):
    c_param = {
        "type": SINGLE_REQUIRED_STRING,
        "reference_number": SINGLE_OPTIONAL_STRING,
        "personal_number": SINGLE_OPTIONAL_STRING,
        "date_of_issuance": OPTIONAL_DATE,
        "date_of_expiry": OPTIONAL_DATE,
        "voucher": OPTIONAL_VOUCHER
    }


def attestation_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, Attestation, sformat)


OPTIONAL_ATTESTATION = (Attestation, False, msg_ser, attestation_deser, False)


# ------------- Vouch -----------------

class Vouch(Evidence):
    c_param = Evidence.c_param.copy()
    c_param.update({
        "validation_method": OPTIONAL_VALIDATION_METHOD,
        "verification_method": OPTIONAL_VERIFICATION_METHOD,
        "verifier": OPTIONAL_VERIFIER,
        "time": OPTIONAL_TIME_STAMP,
        "attestation": OPTIONAL_ATTESTATION
    })


# ------------- ElectronicSignature -----------------

class ElectronicSignature(Evidence):
    c_param = Evidence.c_param.copy()
    c_param.update({
        "signature_type": SINGLE_REQUIRED_STRING,
        "issuer": SINGLE_REQUIRED_STRING,
        "serial_number": SINGLE_REQUIRED_STRING,
        "created_at": OPTIONAL_TIME_STAMP
    })


# ------------- Evidence -----------------


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
    if isinstance(val, Message):
        return val
    elif sformat in ["dict", "json"]:
        if not isinstance(val, str):
            val = json.dumps(val)
            sformat = "json"
    return IdDocument().deserialize(val, sformat)


REQUIRED_ID_DOCUMENT = (IdDocument, True, msg_ser, id_document_deser, False)
OPTIONAL_ID_DOCUMENT = (IdDocument, False, msg_ser, id_document_deser, False)


class Provider(address_claim):
    c_param = address_claim.c_param.copy()
    c_param.update(
        {
            "name": SINGLE_OPTIONAL_STRING,
        }
    )


class AddressClaim(address_claim):
    c_param = address_claim.c_param.copy()
    c_param.update(
        {
            "country_code": SINGLE_OPTIONAL_STRING,
        }
    )


def provider_deser(val, sformat="urlencoded"):
    if isinstance(val, Message):
        return val
    elif sformat in ["dict", "json"]:
        if not isinstance(val, str):
            val = json.dumps(val)
            sformat = "json"
    return Provider().deserialize(val, sformat)


REQUIRED_PROVIDER = (Provider, True, msg_ser, provider_deser, False)


class UtilityBill(Evidence):
    c_param = Evidence.c_param.copy()
    c_param.update({
        "provider": OPTIONAL_SOURCE,
        "date": OPTIONAL_DATE,
        "method": SINGLE_OPTIONAL_STRING,
        "time": OPTIONAL_TIME_STAMP
    })


def utility_bill_deser(val, sformat="json"):
    return deserialize_from_one_of(val, UtilityBill, sformat)


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
    if isinstance(val, Message):
        return val
    elif sformat in ["dict", "json"]:
        if not isinstance(val, str):
            val = json.dumps(val)
            sformat = "json"
    return QES().deserialize(val, sformat)


REQUIRED_QES = (QES, True, msg_ser, qes_deser, False)
OPTIONAL_QES = (QES, False, msg_ser, qes_deser, False)


def address_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, AddressClaim, sformat)


OPTIONAL_ADDRESS = (AddressClaim, False, msg_ser, address_deser, False)

EVIDENCE_TYPES = {
    "document": Document,
    "utility_bill": UtilityBill,
    "electronic_record": ElectronicRecord,
    "electronic_signature": ElectronicSignature,
    "vouch": Vouch
}


class VerificationElement(Message):
    c_param = {
        "trust_framework": SINGLE_REQUIRED_STRING,
        "time": OPTIONAL_TIME_STAMP,
        "verification_process": SINGLE_OPTIONAL_STRING,
        "evidence": OPTIONAL_EVIDENCE_LIST,
    }

    def verify(self, **kwargs):
        _evidence_list = []
        for _args in self.get("evidence", []):
            _evidence = EVIDENCE_TYPES[_args["type"]](**_args)
            _evidence.verify()
            _evidence_list.append(_evidence)

        if _evidence_list:
            self.set_value("evidence", _evidence_list)


def verification_element_deser(val, sformat="dict"):
    if isinstance(val, Message):
        return val
    elif sformat in ["dict", "json"]:
        if not isinstance(val, str):
            val = json.dumps(val)
            sformat = "json"
    return VerificationElement().deserialize(val, sformat)


OPTIONAL_VERIFICATION_ELEMENT = (
    VerificationElement,
    False,
    msg_ser,
    verification_element_deser,
    False,
)


class VerifiedClaims(Message):
    c_param = {"verification": OPTIONAL_VERIFICATION_ELEMENT, "claims": OPTIONAL_IDA_CLAIMS}


SINGLE_OPTIONAL_CLAIMSREQ = (ClaimsRequest, False, msg_ser_json, claims_request_deser, False)

OPTIONAL_VERIFICATION_REQUEST = OPTIONAL_MESSAGE


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


class AssuranceProcess(Message):
    c_param = {
        "policy": SINGLE_OPTIONAL_STRING,
        "procedure": SINGLE_OPTIONAL_STRING,
        "status": SINGLE_OPTIONAL_STRING
    }


def assurance_process_deser(val, sformat="urlencoded"):
    if isinstance(val, Message):
        return val
    elif sformat in ["dict", "json"]:
        if not isinstance(val, str):
            val = json.dumps(val)
            sformat = "json"
    return AssuranceProcess().deserialize(val, sformat)


OPTIONAL_ASSURANCE_PROCESS = (AssuranceProcess, False, msg_ser_json, assurance_process_deser, False)


class VerificationElementRequest(Message):
    c_param = {
        "trust_framework": SINGLE_REQUIRED_STRING,
        "assurance_level": SINGLE_OPTIONAL_STRING,
        "assurance_process": OPTIONAL_ASSURANCE_PROCESS,
        "time": OPTIONAL_TIME_STAMP,
        "verification_process": SINGLE_OPTIONAL_STRING,
        "evidence": OPTIONAL_EVIDENCE_LIST,
    }

    def verify(self, **kwargs):
        super(VerificationElementRequest, self).verify(**kwargs)
        verify_claims_request(self, VerificationElement())


def verification_element_request_deser(val, sformat="urlencoded"):
    return deserialize_from_one_of(val, VerificationElementRequest, sformat)


OPTIONAL_VERIFICATION_ELEMENT_REQUEST = (
    VerificationElementRequest,
    False,
    msg_ser,
    verification_element_request_deser,
    True,
)


class VerifiedClaimsRequest(Message):
    c_param = {"verification": OPTIONAL_MESSAGE, "claims": OPTIONAL_IDA_CLAIMS}

    def verify(self, **kwargs):
        super(VerifiedClaimsRequest, self).verify(**kwargs)
        verify_claims_request(self, VerifiedClaims())


class IDAClaimsRequest(ClaimsRequest):
    def verify(self, **kwargs):
        super(IDAClaimsRequest, self).verify(**kwargs)
        _vc = self.get("verified_claims")
        if _vc:
            _vci = VerifiedClaimsRequest(**_vc)
            _vci.verify()
            self["verified_claims"] = _vci


class ClaimsConstructor:
    def __init__(self, base_class=Message):
        if isinstance(base_class, str):
            self.base_class = importer(base_class)()
        elif isinstance(base_class, Message):
            self.base_class = base_class
        elif type(base_class) == abc.ABCMeta:
            self.base_class = base_class()

        self.info = {}

    def __setitem__(self, key, value):
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

    def to_dict(self):
        res = {}
        for key, val in self.info.items():
            if isinstance(val, ClaimsConstructor):
                res[key] = val.to_dict()
            else:
                res[key] = val
        return res

    def to_json(self):
        return json.dumps(self.to_dict())
