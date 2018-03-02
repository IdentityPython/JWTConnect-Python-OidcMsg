.. _keyjar_howto:

How to use the oidcmsg KeyJar class
***********************************


While the :py:class:`oidcmsg.key_bundle.KeyBundle` class represents a set of keys
with a common origin. The :py:class:`oidcmsg.key_jar.KeyJar` class is
supposed to handle several sets of keys from several different origins.
To do that it connects key bundles to identifiers for their owner.

A KeyJar does not store keys directly it always stores them cloaked in a
KeyBundle.

How to add keys to a KeyJar
---------------------------

One way is to first create a KeyBundle instance and then add it to the
KeyJar. ::

    from oidcmsg.key_jar import KeyJar
    from oidcmsg.key_bundle import keybundle_from_local_file
    >>> kj = KeyJar()
    >>> kb = keybundle_from_local_file(RSAKEY, "rsa", ["sig"])
    >>> kj.add_kb('https://issuer.example.com', kb)
    >>> kj.keys()
    ['https://issuer.example.com']

The two other common cases are adding a symmetric key. In OAuth2/OIDC
this could be the client secret.

    >>> from oidcmsg.key_jar import KeyJar
    >>> kj = KeyJar()
    >>> kj.add_symmetric(owner='', key='client_secret', usage=['sig'])
    >>> kj.keys()
    ['']

Notable with the above is the usage of "" to represent the holder of the
KeyJar instance.

The second use case is that someone has publish a jwks_uri and we want
to add that information to the KeyJar::

    >>> from oidcmsg.key_jar import KeyJar
    >>> kj = KeyJar()
    >>> kj.add_url(owner='https://example.com/op/', url='https://example.com/op/jwks.json')
    >>> kj.keys()
    ['https://example.com/op/']


If you have a set of KeyBundles belonging to an owner then you can add them
all together.::

    >>> from oidcmsg.key_jar import KeyJar
    >>> from oidcmsg.key_bundle import KeyBundle
    >>> desc = {"kty": "oct", "key": "supersecret", "use": "sig"}
    >>> kb1 = KeyBundle([desc])
    >>> kb2 = KeyBundle(source='https://example.com/op/jwks.json')
    >>> kj = KeyJar()
    >>> kj['https://example.com/op/'] = [kb1, kb2]

Note that when you do it this way you over write whatever was
there before. Using one of the 3 first examples will add not replace.

How to get keys out of the KeyJar
---------------------------------

So now you have a KeyJar with lots of keys, how do you get hold of the keys
you need.

For this you have a search interface, where you can specify these things ;

- key_use, default is "sig"
- key_type
- owner, if no owner is given, "" is used as default
- kid
- alg, only used when dealing with elliptic curve keys

An example::

    >>> from oidcmsg.key_bundle import KeyBundle
    >>> print(open('jwks1.json').read())
    {"keys": [
        {
            "n":
                "zkpUgEgXICI54blf6iWiD2RbMDCOO1jV0VSff1MFFnujM4othfMsad7H1kRo50YM5S_X9TdvrpdOfpz5aBaKFhT6Ziv0nhtcekq1eRl8mjBlvGKCE5XGk-0LFSDwvqgkJoFYInq7bu0a4JEzKs5AyJY75YlGh879k1Uu2Sv3ZZOunfV1O1Orta-NvS-aG_jN5cstVbCGWE20H0vFVrJKNx0Zf-u-aA-syM4uX7wdWgQ-owoEMHge0GmGgzso2lwOYf_4znanLwEuO3p5aabEaFoKNR4K6GjQcjBcYmDEE4CtfRU9AEmhcD1kleiTB9TjPWkgDmT9MXsGxBHf3AKT5w",
            "e": "AQAB", "kty": "RSA", "kid": "rsa1", "use": "sig"},
        {
            "k":
                "YTEyZjBlMDgxMGI4YWU4Y2JjZDFiYTFlZTBjYzljNDU3YWM0ZWNiNzhmNmFlYTNkNTY0NzMzYjE",
            "kty": "oct", "use": "sig"}
    ]}
    >>> kb = KeyBundle(source='file://jwks1.json', fileformat='jwks')
    >>> kj = KeyJar()
    >>> kj['https://foo.example.com'] = [kb]
    >>> kj.get(key_use='sig', key_type='rsa', owner='https://foo.example.com')
    [<cryptojwt.jwk.RSAKey object at 0x1049662e8>]
    >>> kj.get('sig', owner='https://foo.example.com')
    [<cryptojwt.jwk.RSAKey object at 0x1049662e8>, <cryptojwt.jwk.SYMKey object at 0x106298cf8>]
    >>> kj.get('sig')
    []


There are a number of shortcut methods you can use:

    - get_signing_key(self, key_type="", owner="", kid=None, \*\*kwargs)
    - get_verify_key(self, key_type="", owner="", kid=None, \*\*kwargs)
    - get_encrypt_key(self, key_type="", owner="", kid=None, \*\*kwargs)
    - get_decrypt_key(self, key_type="", owner="", kid=None, \*\*kwargs)

A very common use case when dealing with OIDC OPs and RPs is that you
have a signed or signed and encrypted JasonWebToken and you need to
decrypt the token and verify the signature. For this there are 2
special methods:

- get_jwt_verify_keys and
- get_jwt_decrypt_keys

You call them like this (assuming *jwt* contains the JasonWebToken and that
*keyjar* is a  KeyJar instance with the necessary keys)::

    from cryptojwt import jws
    _rj = jws.factory(token)
    keys = keyjar.get_jwt_decrypt_keys(_rj.jwt)
    info = rj.verify_compact(token, keys)


