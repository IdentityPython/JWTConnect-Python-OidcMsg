.. oicmsg documentation master file, created by
   sphinx-quickstart on Mon Oct 16 06:28:07 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to oicmsg's documentation!
==================================

This is a module that implements the protocol messages in OpenID Connect/OAuth2.

The base class is the Message class.

The Message class behaves as a dictionary in a number of ways but it alsa
has some special methods.

First an example of the dictionary behavior::

    msg = Message()
    msg['size'] = 42

    msg.keys() = ['size']
    msg.values() = [42]

    msg2 = Message(size=44)
    assert msg['size'] < msg2['size']

Message specification
---------------------

In the OIDC standard for each message there is a list of required or
optional claims. In the Message class this is represented like this::

    class ErrorResponse(Message):
    c_param = {"error": SINGLE_REQUIRED_STRING,
               "error_description": SINGLE_OPTIONAL_STRING,
               "error_uri": SINGLE_OPTIONAL_STRING}

The Error response has 3 claims: error, error_description and error_uri.
*error* is required to be present and is of the type string.
*error_description* and *error_uri* also are strings but they are optional.

SINGLE_REQUIRED_STRING is short hand for::

    SINGLE_REQUIRED_STRING = (basestring, True, None, None, False)

The parts of the tuple are:

1) The data type of the value
2) Whether the claim is required or not
3) The serialization function
4) The deserialization function
5) If the claim can have a NULL value

There are a number of short hand claim value specifications like these::

    SINGLE_REQUIRED_STRING = (basestring, True, None, None, False)
    SINGLE_OPTIONAL_STRING = (basestring, False, None, None, False)
    SINGLE_OPTIONAL_INT = (int, False, None, None, False)
    OPTIONAL_LIST_OF_STRINGS = ([basestring], False, list_serializer,
                                list_deserializer, False)
    REQUIRED_LIST_OF_STRINGS = ([basestring], True, list_serializer,
                                list_deserializer, False)
    OPTIONAL_LIST_OF_SP_SEP_STRINGS = ([basestring], False,
                                       sp_sep_list_serializer,
                                       sp_sep_list_deserializer, False)
    REQUIRED_LIST_OF_SP_SEP_STRINGS = ([basestring], True,
                                       sp_sep_list_serializer,
                                       sp_sep_list_deserializer, False)
    SINGLE_OPTIONAL_JSON = (basestring, False, json_serializer,
                            json_deserializer, False)


The serialize function is expected to convert the internal Python representation
of the value to a suitable on-the-wire representation.

The deserialization function then does the opposite. It will take an
on-the-wire representation and convert it to it's internal representation.

If one adds a claim to a Message instance that has a name that is not in the
c_param dictionary then only simple data types are possible and there can be
not verification of the correctness of the value.

It is possible to limit the set of value a claim can have::

    class TokenErrorResponse(ErrorResponse):
    c_allowed_values = {"error": ["invalid_request", "invalid_client",
                                  "invalid_grant", "unauthorized_client",
                                  "unsupported_grant_type",
                                  "invalid_scope"]}


Here the values of *error* is limited to a specified set of values.

One can also set default value::

    class AccessTokenRequest(Message):
    c_param = {
        "grant_type": SINGLE_REQUIRED_STRING,
        "code": SINGLE_REQUIRED_STRING,
        "redirect_uri": SINGLE_REQUIRED_STRING,
        "client_id": SINGLE_OPTIONAL_STRING,
        "client_secret": SINGLE_OPTIONAL_STRING,
        'state': SINGLE_OPTIONAL_STRING
    }
    c_default = {"grant_type": "authorization_code"}

The interpretation of this is that if *grant_type* is not set it should be
treated as if it had the value *authorization_code*.

Import/export
-------------

There are a number of methods defined in the Message class that can be used
to export or import information.

Import
++++++

- from_dict
- from_json
- from_jwe
- from_jwt
- from_urlencoded

from_dict
.........

Imports a dictionary.

.. toctree::
   :maxdepth: 2
   :caption: Contents:



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
