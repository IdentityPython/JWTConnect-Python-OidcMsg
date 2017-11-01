.. _keybundle_howto:

How to use the oicmsg KeyBundle class
*************************************

The :py:class:`oicmsg.keybundle.KeyBundle` class represents a set of keys
with a common origin.

When initiating a class instance it can be fed with key descriptions or
the name of a local file containing one or more keys in some know format
of a URL pointing to a web page that contains key descriptions in the
form of a JWKS.

When supplying a file name or a URL the class instance can be updated by
rereading the file or the web page.

Using a keys description
------------------------

Loading a symmetric key::

    >>> desc = {"kty": "oct", "key": "supersecret", "use": "sig"}
    >>> from oicmsg.key_bundle import KeyBundle
    >>> kb = KeyBundle([desc])
    >>> kb.keys()
    [<jwkest.jwk.SYMKey object at 0x1037f7080>]

Loading from a file::

