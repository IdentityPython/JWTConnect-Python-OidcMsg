__author__ = 'Roland Hedberg'


class OicMsgError(Exception):
    def __init__(self, errmsg, content_type="", *args):
        Exception.__init__(self, errmsg, *args)
        self.content_type = content_type


class MissingAttribute(OicMsgError):
    pass


class UnsupportedMethod(OicMsgError):
    pass


class MissingParameter(OicMsgError):
    pass


class UnknownAssertionType(OicMsgError):
    pass


class ParameterError(OicMsgError):
    pass


class URIError(OicMsgError):
    pass


class ParseError(OicMsgError):
    pass


class FailedAuthentication(OicMsgError):
    pass


class NotForMe(OicMsgError):
    pass


class UnSupported(Exception):
    pass


class MessageException(OicMsgError):
    pass


class IssuerMismatch(OicMsgError):
    pass


class RestrictionError(OicMsgError):
    pass


class InvalidRedirectUri(Exception):
    pass


class MissingPage(Exception):
    pass


class ModificationForbidden(Exception):
    pass


class RegistrationError(OicMsgError):
    pass


class CommunicationError(OicMsgError):
    pass


class RequestError(OicMsgError):
    pass


class AuthnToOld(OicMsgError):
    pass


class ImproperlyConfigured(OicMsgError):
    pass


class SubMismatch(OicMsgError):
    pass


class FormatError(OicMsgError):
    pass


class VerificationError(OicMsgError):
    pass


class MissingRequiredValue(MessageException):
    pass


class MissingSigningKey(OicMsgError):
    pass


class TooManyValues(MessageException):
    pass


class DecodeError(MessageException):
    pass


class GrantExpired(OicMsgError):
    pass


class OldAccessToken(OicMsgError):
    pass


class SchemeError(MessageException):
    pass


class NotAllowedValue(MessageException):
    pass


class WrongSigningAlgorithm(MessageException):
    pass


class WrongEncryptionAlgorithm(MessageException):
    pass


class MissingRequiredAttribute(MessageException):
    def __init__(self, attr, message=""):
        Exception.__init__(self, attr)
        self.message = message

    def __str__(self):
        return "Missing required attribute '%s'" % self.args[0]


class InvalidRequest(OicMsgError):
    pass


class KeyIOError(OicMsgError):
    pass


class UnknownKeyType(KeyIOError):
    pass


class UpdateFailed(KeyIOError):
    pass


