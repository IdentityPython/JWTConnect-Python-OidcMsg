from cryptojwt import jwt

from oicmsg.oic import JsonWebToken

__author__ = 'Roland Hedberg'


class JWT(jwt.JWT):
    msg_cls = JsonWebToken

    def __init__(self, keyjar, iss='', lifetime=0, sign_alg='RS256',
                 encrypt=False, enc_enc="A128CBC-HS256", enc_alg="RSA1_5"):
        jwt.JWT.__init__(self, own_keys=None, iss=iss, rec_keys=None,
                         lifetime=lifetime, sign_alg=sign_alg, encrypt=encrypt,
                         enc_enc=enc_enc, enc_alg=enc_alg)
        self.keyjar = keyjar

    def receiver_keys(self, receiver):
        return self.keyjar.get_issuer_keys(receiver)

    def receivers_keys(self):
        res = {}
        for owner in self.keyjar.owners():
            if owner == '':
                continue
            else:
                res[owner] = self.keyjar.get_issuer_keys(owner)
        return res

    def my_keys(self):
        return self.keyjar.get_issuer_keys('')

    # def _encrypt(self, payload, cty='JWT'):
    #     keys = self.keyjar.get_encrypt_key(owner='')
    #     kwargs = {"alg": self.enc_alg, "enc": self.enc_enc}
    #
    #     if cty:
    #         kwargs["cty"] = cty
    #
    #     # use the clients public key for encryption
    #     _jwe = JWE(payload, **kwargs)
    #     return _jwe.encrypt(keys, context="public")
    #
    # def pack_init(self):
    #     """
    #     Gather initial information for the payload.
    #
    #     :return: A dictionary with claims and values
    #     """
    #     argv = {'iss': self.iss, 'iat': utc_time_sans_frac()}
    #     if self.lifetime:
    #         argv['exp'] = argv['iat'] + self.lifetime
    #     return argv
    #
    # def pack_key(self, owner='', kid=''):
    #     """
    #     Find a key to be used for signing the Json Web Token
    #
    #     :param owner: Owner of the keys to chose from
    #     :param kid: Key ID
    #     :return: One key
    #     """
    #     keys = self.keyjar.get_signing_key(jws.alg2keytype(self.sign_alg),
    #                                        owner=owner, kid=kid)
    #
    #     if not keys:
    #         raise NoSuitableSigningKeys('kid={}'.format(kid))
    #
    #     return keys[0]  # Might be more then one if kid == ''
    #
    # def pack(self, payload=None, kid='', owner='', cls_instance=None, **kwargs):
    #     """
    #
    #     :param payload: Information to be carried as payload in the JWT
    #     :param kid: Key ID
    #     :param owner: The owner of the the keys that are to be used for signing
    #     :param cls_instance: This might be a instance of a class already
    #         prepared with information
    #     :param kwargs: Extra keyword arguments
    #     :return: A signed or signed and encrypted JsonWebtoken
    #     """
    #     _args = self.pack_init()
    #
    #     if self.sign_alg != 'none':
    #         _key = self.pack_key(owner, kid)
    #         _args['kid'] = _key.kid
    #     else:
    #         _key = None
    #
    #     try:
    #         _encrypt = kwargs['encrypt']
    #     except KeyError:
    #         _encrypt = self.encrypt
    #     else:
    #         del kwargs['encrypt']
    #
    #     if 'jti' in self.message_type.c_param:
    #         try:
    #             _jti = kwargs['jti']
    #         except KeyError:
    #             _jti = uuid.uuid4().hex
    #
    #         _args['jti'] = _jti
    #
    #     if payload is not None:
    #         _args.update(payload)
    #
    #     if cls_instance:
    #         cls_instance.update(_args)
    #         _jwt = cls_instance
    #     else:
    #         _jwt = self.message_type(**_args)
    #
    #     _jws = _jwt.to_jwt([_key], self.sign_alg)
    #     if _encrypt:
    #         return self._encrypt(_jws)
    #     else:
    #         return _jws
    #
    # def _verify(self, rj, token):
    #     keys = self.keyjar.get_jwt_verify_keys(rj.jwt)
    #     return rj.verify_compact(token, keys)
    #
    # def _decrypt(self, rj, token):
    #     """
    #     Decrypt an encrypted JsonWebToken
    #
    #     :param rj: :py:class:`cryptojwt.jwe.JWE` instance
    #     :param token: The encrypted JsonWebToken
    #     :return:
    #     """
    #     keys = self.keyjar.get_jwt_decrypt_keys(rj.jwt)
    #     return rj.decrypt(token, keys=keys)
    #
    # def unpack(self, token):
    #     """
    #     Unpack a received signed or signed and encrypted Json Web Token
    #
    #     :param token: The Json Web Token
    #     :return: If decryption and signature verification work the payload
    #         will be returned as a Message instance.
    #     """
    #     if not token:
    #         raise KeyError
    #
    #     _rj = jwe.factory(token)
    #     if _rj:
    #         token = self._decrypt(_rj, token)
    #
    #     _rj = jws.factory(token)
    #     if _rj:
    #         info = self._verify(_rj, token)
    #     else:
    #         raise Exception()
    #
    #     if self.message_type:
    #         return self.message_type(**info)
    #     else:
    #         return info
