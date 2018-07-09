from cryptojwt import jwt

from oidcmsg.oidc import JsonWebToken

__author__ = 'Roland Hedberg'


class JWT(jwt.JWT):
    def __init__(self, keyjar, iss='', lifetime=0, sign=True, sign_alg='RS256',
                 encrypt=False, enc_enc="A128CBC-HS256", enc_alg="RSA1_5",
                 msg_cls=JsonWebToken, iss2msg_cls=None):
        jwt.JWT.__init__(self, own_keys=None, iss=iss, rec_keys=None,
                         lifetime=lifetime, sign=sign, sign_alg=sign_alg,
                         encrypt=encrypt, enc_enc=enc_enc, enc_alg=enc_alg,
                         msg_cls=msg_cls, iss2msg_cls=iss2msg_cls)
        self.keyjar = keyjar

    def receiver_keys(self, receiver):
        """
        Get all the keys I have for a specific entity

        :param receiver: The entity ID
        :return: A list of keys
        """
        return self.keyjar.get_issuer_keys(receiver)

    def receivers_keys(self):
        """
        Reorganize all the keys in the key jar into a dictionary disregarding
        keybundle dependencies. The keys of the dictionary are the isseur IDs
        and the values are all the keys that are connected to a specific
        issuer.

        :return: A dictionary
        """
        res = {}
        for owner in self.keyjar.owners():
            if owner == '':
                continue
            else:
                res[owner] = self.keyjar.get_issuer_keys(owner)
        return res

    def my_keys(self, id=''):
        """
        My default issuer/entity ID in the key jar is ''

        :param id: An entity ID
        :return: A list of keys
        """
        return self.keyjar.get_issuer_keys(id)

