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

    >>> from oicmsg.key_bundle import KeyBundle
    >>> desc = {"kty": "oct", "key": "supersecret", "use": "sig"}
    >>> kb = KeyBundle([desc])
    >>> kb.keys()
    [<jwkest.jwk.SYMKey object at 0x1037f7080>]

Loading from a file::

    >>> from oicmsg.key_bundle import KeyBundle
    >>> print(open('jwks.json').read())
    {
      "keys": [
        {
          "kty": "RSA",
          "e": "AQAB",
          "use": "enc",
          "n": "inLw-BGYXhic6qS__NBRDfCqFF07lyyBO_tyoBk_EqVoyog03NzcBsKbOHFS3mtu81uBzyDA_lzVZGOacovYo3zteo2o1JrJ97LpgOa1CDgxR8KpzDXiWRRbkkIG7JvO_h9ghCfZghot-kn5JLgCRAbuMhiRT2ojdhU_nhjywI0"
        },
        {
          "kty": "RSA",
          "e": "AQAB",
          "use": "sig",
          "n": "0eAoiw_xP35yXeJJSNrjhplu32XhEaRpYIshCP-8FvktNnbULFKF_2hHQ7c7iPpmZS7-U8zEQn3O-ZrVDw9u4Ito0FvQ2fw7eZNNxsb8WlZHW07e_y2xByYfwfQhk3Nn9yqb5xSfdaVAUaRFPFSxE_gOu6iaWGp8lz-fyznxaDk"
        }
      ]
    }
    >>> kb = KeyBundle(source='file://jwks.json', fileformat='jwks')
    >>> len(kb)
    2
    >>> kb.keys()
    [<jwkest.jwk.RSAKey object at 0x1048a62b0>, <jwkest.jwk.RSAKey object at 0x1048d3c50>]


and if DER encoded RSA key file instead::

    >>> from oicmsg.key_bundle import KeyBundle
    >>> print(open('keys/rsa_enc.pub').read())
    -----BEGIN RSA PUBLIC KEY-----
    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8J/Zxwi86zUGgv1KwSz17SHIA
    0jrVUbZY+heNJJXX+vo60me1j4TsAjhjqqwsVsbXsGPn8Ag/vjDIDFdEL2e9clPJ
    IZsF+/l+F1yIq3Ne5p9r3FJtN5R0lbCegjG1WyJbr/4Xsr8pxojDEXdGDVzFlC2M
    chR2Erhf/gRicOFe9wIDAQAB
    -----END RSA PUBLIC KEY-----
    >>> kb = KeyBundle(source='file://keys/rsa_enc.pub', fileformat='der', keyusage=['sig'])
    >>> len(kb)
    1
    >>> kb.keys()
    [<jwkest.jwk.RSAKey object at 0x1048a65c0>]

**Note** that is no keyusage had been defined then two copies of the
RSA key would have been been stored in the key bundle. One for
signing/verifying and the other for encryption/decryption.


