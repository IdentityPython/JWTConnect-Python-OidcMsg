.. _keybundle_howto:

How to use the oicmsg KeyBundle class
*************************************

The :py:class:`oicmsg.key_bundle.KeyBundle` class represents a set of keys
with a common origin.

The idea behind the class is that it should be the link between a set of
keys and the OIDC client library.
It works by on one hand keeping an internal representation of the keys in sync
with a specific external representation (the external version representing the
correct state of the key) and on the other hand provide an API for accessing
the keys.
The reason for key sets to change are regular key roll-over or as a result of
key compromise.

When initiating a class instance it can be fed with key descriptions or
the name of a local file containing one or more keys in some know format
of a URL pointing to a web page that contains key descriptions in the
form of a JWKS.

When supplying a file name or a URL the class instance can be updated by
rereading the file or the web page.

Initiating a key bundle
-----------------------

Loading a symmetric key::

    >>> from oicmsg.key_bundle import KeyBundle
    >>> desc = {"kty": "oct", "key": "supersecret", "use": "sig"}
    >>> kb = KeyBundle([desc])
    >>> kb.keys()
    [<cryptojwt.jwk.SYMKey object at 0x1037f7080>]

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
    [<cryptojwt.jwk.RSAKey object at 0x1048a62b0>, <cryptojwt.jwk.RSAKey object at 0x1048d3c50>]


and if DER encoded RSA key file instead::

    >>> from oicmsg.key_bundle import KeyBundle
    >>> print(open('keys/rsa_enc.pub').read())
    -----BEGIN RSA PUBLIC KEY-----
    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8J/Zxwi86zUGgv1KwSz17SHIA
    0jrVUbZY+heNJJXX+vo60me1j4TsAjhjqqwsVsbXsGPn8Ag/vjDIDFdEL2e9clPJ
    IZsF+/l+F1yIq3Ne5p9r3FJtN5R0lbCegjG1WyJbr/4Xsr8pxojDEXdGDVzFlC2M
    chR2Erhf/gRicOFe9wIDAQAB
    -----END RSA PUBLIC KEY-----
    >>> kb = KeyBundle(source='keys/rsa_enc.pub', fileformat='der', keyusage=['sig'])
    >>> len(kb)
    1
    >>> kb.keys()
    [<cryptojwt.jwk.RSAKey object at 0x1048a65c0>]

**Note** that if no *keyusage* had been defined then two copies of the
RSA key would have been been stored in the key bundle. One for
signing/verifying and the other for encryption/decryption.

Updating a key bundle
---------------------

Over time the information in a key bundle may grove stale. Therefor
the class instance has cache time set and knows when it last was updated.
Whenever a key bundle is asked for information about the keys it keeps it
will check if it is time to update the key cache.

To updated means rereading information from the source file or getting
the last information from the web page.

If you initiated with key descriptions then no update can be made unless you
manually delete, or mark as inactive, the old keys and load new key
descriptions.::

    >>> from oicmsg.key_bundle import KeyBundle
    >>> desc = {"kty": "oct", "key": "supersecret", "use": "sig"}
    >>> kb = KeyBundle([desc])
    >>> kb.keys()
    [<cryptojwt.jwk.SYMKey object at 0x1037f7080>]
    >>> for k in kb.keys():
    ...     kb.remove(k)
    ...
    >>> kb.keys()
    []
    >>> desc = {"kty": "oct", "key": "secret", "use": "enc"}
    >>> kb.do_keys([desc])
    >>> kb.keys()
    [<cryptojwt.jwk.SYMKey object at 0x106298cf8>]

or::

    >>> from oicmsg.key_bundle import KeyBundle
    >>> desc = {"kty": "oct", "key": "supersecret", "use": "sig"}
    >>> kb = KeyBundle([desc])
    >>> for k in kb.keys():
    ...     kb.mark_as_inactive(k.kid)
    ...
    >>> len(kb.keys())
    1
    >>> desc = {"kty": "oct", "key": "secret", "use": "enc"}
    >>> kb.do_keys([desc])
    >>> len(kb.keys())
    2
    >>> len(kb.active_keys())
    1


Getting access to keys
----------------------

To pick out one key based on the Key Identifier (kid) you can do this::

    >>> from oicmsg.key_bundle import KeyBundle
    >>> print(open('jwks1.json').read())
    {"keys": [
        {
            "n":
                "zkpUgEgXICI54blf6iWiD2RbMDCOO1jV0VSff1MFFnujM4othfMsad7H1kRo50YM5S_X9TdvrpdOfpz5aBaKFhT6Ziv0nhtcekq1eRl8mjBlvGKCE5XGk-0LFSDwvqgkJoFYInq7bu0a4JEzKs5AyJY75YlGh879k1Uu2Sv3ZZOunfV1O1Orta-NvS-aG_jN5cstVbCGWE20H0vFVrJKNx0Zf-u-aA-syM4uX7wdWgQ-owoEMHge0GmGgzso2lwOYf_4znanLwEuO3p5aabEaFoKNR4K6GjQcjBcYmDEE4CtfRU9AEmhcD1kleiTB9TjPWkgDmT9MXsGxBHf3AKT5w",
            "e": "AQAB", "kty": "RSA", "kid": "rsa1"},
        {
            "k":
                "YTEyZjBlMDgxMGI4YWU4Y2JjZDFiYTFlZTBjYzljNDU3YWM0ZWNiNzhmNmFlYTNkNTY0NzMzYjE",
            "kty": "oct"}
    ]}
    >>> kb = KeyBundle(source='file://jwks1.json', fileformat='jwks')
    >>> kb.get_key_with_kid('rsa1')
    <cryptojwt.jwk.RSAKey object at 0x1049662e8>
    >>> k = kb.get_key_with_kid('rsa1')
    >>> k.kid
    'rsa1'
    >>> k.kty
    'RSA'

Get all keys of specific type (note that here the JWKS describes private keys)::

    >>> from oicmsg.key_bundle import KeyBundle
    >>> print(open('jwks2.json').read())
    {
      "keys": [
        {
          "use": "enc",
          "n": "z7TYSonR4KTijDVTJJHBRs_7MUtvy2_aIPOKpkbigerOYxk7DQ9zNeaFUzFt8Pz-SCPItEcFXXIrCOm3IlyDh-yYZsMmSQhdIGneGF7DCr2NnpbF4k25VAne516t9ogCCdxvvFkqVVh2oi_lxZtXEnELqz3SsCzV5fKvxQSo8NycSe3kjBHFmLGwSILzUMeSzYjpbC7SEnYVFpVfz0LmxfDTkLWL8-uE55Qxo7BFkbRIuqUdlpEYrb7lMPKpP7BvCcIy6lXg7tyX1g-wPmsiFJlojXTWU-xWEafEwXLJ7l-YTBMQDyEYSgDBT9f-Motj6ZtwIsB0aG6tHLoXWdFqOQ",
          "q": "_UCFtRnO9UbmxyVLX9Sq2_qI5WhXTTH2G5KWn-tA-j7xuvurqcx6IKm8yxDHKk1iDgORSkFUcOjP5B249jPR8_MpWl9VPbkpc-Kp41hqsI_8tqaTm-nmwG8KGukOnVX98BJ6EyGWlEYDlXPsEU58H1r3M9B6AbXwShCB1qomBf0",
          "e": "AQAB",
          "kty": "RSA",
          "kid": "Jb8ZVEFoN1OZjdMoO6H7csDR8UPRtwgmXV6i2uzbGkY",
          "d": "ESgxk5qlzQYhto4zE3q8ueI1MCG4ltfi70Tex5RkYnHoYXQ0lgQYMrQbgD89gyIKyR-3lPim30yudFqF5583uDMZdaeaEn9P3f0QvPea6di1iYuPxf1AmUoFcRw3h309md3tFuRQpGMdzZDiTHvj6eCPo7IEJMxXUNrGnSIg6GBSf1N4-eV9-hBw0zUNi6qY4DdnK4g9qWkn2xSRORxH7ihUWffakyE_ZWlvxFP70cbYeGE-N9gD9DnIcgGvy-A1cXSXqqaPytzVa9cUzwPV6h5goA86Iq135yKCEeRkvl8r_jU20JQJvXyfQFJC9WHl8coPTI9PQCJFDNjlv5z_uQ",
          "p": "0fXOmXOEAgSMtP6GxgbN-cVYDMQ9_ExyM28Gp_pBwy0EOfpYkhITnaqvdN3H-TTTgZ1XkAlNmC0TqztF6Mmd3mNGWBgUN8vEGpRMinnqXNrUgh5_tWr2crsdqmTRegrZVCyVUm_CQSvQHft8i8yidqzDud5XModLSEC8olyMC-0"
        },
        {
          "use": "sig",
          "n": "sTmvermNFgmCErMP-Eo5a1CWlR69N_eEcEWMlSW2JTwyQK7Ao5ulcNs730O2M6BTrZOqH146heN9XQoYQVfdzgVTuuA9ivRfdazAh7SpMPCp4WtxG-eVuaWNDPKWFf8NHkU83Wpq3UyYtAWxE-Cm3KPlY5HlU3MAr9rv5uLUm7bHjHBl2PaVMfGrNquSImocD7N9pvgoUjM6hHfhCS9MGn3ulYBeWueMlMR3mwQTgNnKcYY4lChgQz8cB2pUADWIAfM1Rour_Xwv_aHlnhM1BvP0mG65WeB8NcCqYZYPDpp48og6SjmNLfSiVaUubChJ9Bv0mpQUxRX5a_hKph64Dw",
          "q": "5uWOdbicks_BIImjfx2Q0eXkxnCVWpCyuVDFQbP5xHkN3SWgv9146U9zDdc414RT4SaGuC3H7whO0ph48izuwUkqVZATkGLYPjRj3z0QMRUm_WTKJNDyGoK2weA82xVcUsCfWX_n7QE6GLa5RR4eOL_pqe1MFTJpzOuYXU5bbN0",
          "e": "AQAB",
          "kty": "RSA",
          "kid": "QTxQZYpSX_HLmP_piD3k8aP8bq0vfwy3wXTnfrz8Qlc",
          "d": "GoeSm7H8C0D4Hjl82gOubcCeEguMcrzUMARRQ6BmEFPfB-zA_JzXmrnO0CCwPTEyZYj1zgVKiHFh-lQBBoMTOnx0qMRZohvr0E9AcPAb5a4ZGBv_zhgQQz6jiz0jN367JX1i25hLD_6f208Az4NxJxVHyOx1olTUVP7Wq77n6bkmUnI0VKbdVO6MDmwDjdsynt2kRGEsRdPNvDhUsBxwesqjSrrawwLGILGYveno-i2saFHihFFpBO58OVnJXzowSne_9SKI01PH2PYHrmc-rE6lxmwIysbguS9H0YvygWxx0es3_G3gqjrRZsSqXNuVxyfJSAESKQQMnhIE1m-N3Q",
          "p": "xH5RaAwfjt5ZsWn626mxtHh5vEmKdqBY0DcnTmpUSvfLXtzhIf8lnyy-hBFbFUKH2mSng-QqyIHjsTPQAGAD-VCgoATleIsPKYSDOUqB2H7v-CBTLEDQiuaj9PuiIsEuGEBCuVGLR2yvy9iquVED9SILynro4S8DIVfLUkcKA9s"
        },
        {
          "y": "CK7MZC1WqmrX9NFVkqp2ONXri-7ex-zRR0TNrnZ1XGo",
          "use": "sig",
          "crv": "P-256",
          "kty": "EC",
          "kid": "dat3aVDlZO57WjObkuvdk1ipku6g4pNOWJ6_vnVoX1A",
          "d": "H5evN3jPEtSURbpzlp23RJ0gTMSg-fUxMdWczA9u38U",
          "x": "FZCtFh6QmoHZ8vmQiDFOVIOEBqr9Lokqw_yLFB8oq3Y"
        }
      ]
    }
    >>> kb = KeyBundle(source='jwks2.json', fileformat='jwks')
    >>> kb.get('oct')
    []
    >>> kb.get('rsa')
    [<cryptojwt.jwk.RSAKey object at 0x104f39198>, <cryptojwt.jwk.RSAKey object at 0x104f39208>]
    >>> kb.get('ec')
    [<cryptojwt.jwk.ECKey object at 0x10585d908>]

- 'oct' is the name  for symmetric keys,
- 'rsa' for RSA keys and
- 'ec' for Elliptic Curve keys


Other things you can do
-----------------------

You can construct a JWKS from the keys in a KeyBundle instance like this::

    >>> from oicmsg.key_bundle import KeyBundle
    >>> kb = KeyBundle(source='file://keys/rsa_enc.pub', fileformat='der', keyusage=['sig'])
    >>> print(kb.jwks())
    {"keys": [{"n": "vCf2ccIvOs1BoL9SsEs9e0hyANI61VG2WPoXjSSV1_r6OtJntY-E7AI4Y6qsLFbG17Bj5_AIP74wyAxXRC9nvXJTySGbBfv5fhdciKtzXuafa9xSbTeUdJWwnoIxtVsiW6_-F7K_KcaIwxF3Rg1cxZQtjHIUdhK4X_4EYnDhXvc", "kty": "RSA", "use": "sig", "e": "AQAB"}]}


