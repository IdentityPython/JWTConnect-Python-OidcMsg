from cryptojwt import jwt

from oicmsg.oic import JsonWebToken

__author__ = 'Roland Hedberg'


class JWT(jwt.JWT):
    msg_cls = JsonWebToken

    def __init__(self, keyjar, iss='', lifetime=0, sign=True, sign_alg='RS256',
                 encrypt=False, enc_enc="A128CBC-HS256", enc_alg="RSA1_5",
                 msg_cls=None, iss2msg_cls=None):
        jwt.JWT.__init__(self, own_keys=None, iss=iss, rec_keys=None,
                         lifetime=lifetime, sign_alg=sign_alg, encrypt=encrypt,
                         enc_enc=enc_enc, enc_alg=enc_alg, msg_cls=msg_cls,
                         iss2msg_cls=iss2msg_cls, sign=sign)
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

