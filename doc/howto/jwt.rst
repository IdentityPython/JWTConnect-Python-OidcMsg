.. _jwt_howto:

How to use the oicmsg JWT class
*******************************

This is the base class for handling signing or signing and encrypting JSON Web
Token.

A simple example::

    >>> from oicmsg.key_jar import KeyJar
    >>> from oicmsg.jwt import JWT
    >>> kj = KeyJar()
    >>> kj.add_symmetric(owner='', key='client_secret', usage=['sig'])
    >>> kj['https://fedop.example.org'] = kj['']
    >>> issuer = 'https://fedop.example.org'
    >>> srv = JWT(kj, iss=issuer, sign_alg="HS256")
    >>> payload = {'sub': 'sub2'}
    >>> _jwt = srv.pack(payload=payload)
    >>> info = srv.unpack(_jwt)
    >>> print(info)
    {'sub': 'sub2', 'iss': 'https://fedop.example.org',
    'jti': 'c9548d1d0da64b39a21753a095688248', 'iat': 1510344124}


In the above example we first create a KeyJar instance and loads it with
one symmetric key. The KeyJar stores the keys under identifiers. The
identifier for the local entity is the empty string ''.

The reason for storing the symmetric key under 2 different identifiers (in
line 5) is that when the unpacking is done (line 10) the
:py:class:`oicmsg.jwt.JWT` instance will look at the payload of the json web
token to see who the issuer of the json web token is and then use that
identifier when searching for keys in the KeyJar that can be used for verifying
the signature on the json web token.

*info* which is returned by the unpack method is actually a
:py:class:`oicmsg.oic.JsonWebToken`
instance. So you can do a bit more with it like you can see what the header
of the json web token looked like::

    >>> print(info.jws_header)
    {'alg': 'HS256'}

and you can verify the correctness of the json web token::

    >>> print(info.verify())
    True

Now in this simple example that doesn't give you much.