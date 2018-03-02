.. _oidcmsg_howto:

How to use the oidcmsg Message class
************************************

Basic usage
-----------

An oidcmsg :py:class:`oidcmsg.message.Message` instance have some
functionality common with Python dictionaries.
So you can do things like assign values to a key::

    >>> from oidcmsg.message import Message
    >>> msg = Message()
    >>> msg['key'] = 'value'

And you can read a value assigned to a key::

    >>> from oidcmsg.message import Message
    >>> msg = Message()
    >>> msg['key'] = 'value'
    >>> val = msg['key']
    >>> print(val)
    value

:py:class:`oidcmsg.message.Message` also supports other dictionary
methods::

    >>> from oidcmsg.message import Message
    >>> msg = Message()
    >>> msg['key'] = 'value'
    >>> list(msg.keys())
    ['key']
    >>> list(msg.items())
    [('key', 'value')]
    >>> 'key' in msg
    True
    >>> print(msg)
    {'key': 'value'}

    >>> msg['another'] = 2
    >>> msg.keys()
    dict_keys(['another', 'key'])
    >>> msg.values()
    dict_values([2, 'value'])
    >>> del msg['key']
    >>> print(msg)
    {'another': 2}

Like a dictionary one can also do::

    >>> from oidcmsg.message import Message
    >>> msg = Message(key='value', other=6)
    >>> print(msg)
    {'other': 6, 'key': 'value'}


Serialization/deserialization
-----------------------------

Since instances of :py:class:`oidcmsg.message.Message` will be used
in an environment where information are to be sent over a wire it must be
possible to serialize the information in such an instance to a format that
can be transmitted over-the-wire.

Because of this a number of method has been added to support serialization to
and deserialization from a number of representations that are used in the
OAuth2 and OIDC protocol exchange.

The format supported are:

- JSON
- urlencoded
- Jason Web Token (JWT) signed and/or encrypted.

An example using url encoding::

    >>> from oidcmsg.message import Message
    >>> msg = Message()
    >>> msg['key'] = 'value'
    >>> msg['another'] = 2
    >>> msg.to_urlencoded()
    'another=2&key=value'

    >>> urlenc = msg.to_urlencoded()
    >>> recmsg = Message().from_urlencoded(urlenc)
    >>> print(recmsg)
    {'key': 'value', 'another': '2'}


Same thing using JSON::

    >>> from oidcmsg.message import Message
    >>> msg = Message(key='value', another=2)
    >>> msg.to_urlencoded()
    'another=2&key=value'

    >>> json_msg = msg.to_json()
    >>> recmsg = Message().from_json(json_msg)
    >>> print(recmsg)
    {'another': 2, 'key': 'value'}


Regarding signed Jason Web Tokens we need a key so I create a
simple symmetric one:

    >>> from oidcmsg.message import Message
    >>> from cryptojwt.jwk import SYMKey
    >>> msg = Message(key='value', another=2)
    >>> keys = [SYMKey(key="A1B2C3D4")]

    >>> jws = msg.to_jwt(keys, "HS256")
    >>> print(jws)
    eyJhbGciOiJIUzI1NiJ9.eyJrZXkiOiAidmFsdWUiLCAiYW5vdGhlciI6IDJ9.-yoKjzgRxQu0KqyH-6wRNB8g6W7PSu2cbHRguCjc18k

    >>> recv = Message().from_jwt(jws, key=keys)
    >>> print(recv)
    {'another': 2, 'key': 'value'}

Verifying the message content
-----------------------------

A protocol specification would not be anything if it didn't specify
what a message is supposed to look like. Which attributes that can occur in
a message and what type of values the attributes could have. And in
some extreme case the specification can also specify the exact values that
a specific attribute can have.

The OAuth2 and OpenID Connect specifications does all that.
But both of them also states that extra attributes can always occur and
should be allowed.

A :py:class:`oidcmsg.message.Message` class ínstance can deal with this.

Let's take the basic error response as an example. This message
is defined thus in oidcmsg::

    class ErrorResponse(Message):
    c_param = {"error": SINGLE_REQUIRED_STRING,
               "error_description": SINGLE_OPTIONAL_STRING,
               "error_uri": SINGLE_OPTIONAL_STRING}

What this means is that *error* must have a string value and that
*error_description* and *error_uri* may have values and if so single
string values.

What does this look like then::

    >>> from oidcmsg.oauth2 import ErrorResponse
    >>> err = ErrorResponse(error='invalid_request')
    >>> err.verify()
    True

So with error defined the verify method will evaluate to True.
If we forget to provide the *error* attribute::

    >>> err = ErrorResponse(error_description='Some strange error')
    >>> err.verify()
    Traceback (most recent call last):
      File "/Library/Frameworks/Python.framework/Versions/3.6/lib/python3.6/site-packages/oidcmsg-0.1.0-py3.6.egg/oidcmsg/message.py", line 617, in verify
        val = self._dict[attribute]
    KeyError: 'error'

    During handling of the above exception, another exception occurred:

    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File "/Library/Frameworks/Python.framework/Versions/3.6/lib/python3.6/site-packages/oidcmsg-0.1.0-py3.6.egg/oidcmsg/message.py", line 620, in verify
        raise MissingRequiredAttribute("%s" % attribute)
    oidcmsg.exception.MissingRequiredAttribute: Missing required attribute 'error'

an exception will be raised.

If you provide extra attributes, that is OK but those attributes can not be
verified.

    >>> from oidcmsg.oauth2 import ErrorResponse
    >>> err = ErrorResponse(error='invalid_request', error_code=500)
    >>> err.verify()
    True
    >>> print(err)
    {'error': 'invalid_request', 'error_code': 500}


