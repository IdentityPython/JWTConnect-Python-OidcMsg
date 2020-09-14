# oidcmsg
Implementation of OIDC protocol messages.

oidcmsg is the 2nd layer in the
JwtConnect stack (cryptojwt, oidcmsg, oidcservice, oidcrp)

Handles serialising into a couple of formats (jwt, json, urlencoded and dict) and deserialising from said formats.

It also does verification of messages , that is :

+ verifies that all the required parameters are present and has a value
+ verifies that the parameter values are of the right type
+ verifies that if there is a list of permitted values, a parameter value is on 
that list.

and finally if the value is a signed and/or encrypted JWT this package
will perform the necessary decryption and signature verification. 


Also implements a **KeyJar** which keeps keys belonging to 
different owners. One owner may have many keys.
If some of these keys have a common origin, like described in a JWKS.
Such a set will be kept in a **keyBundle**.
Also implemented in this package. 
   
Please read the [Official Documentation](https://oidcmsg.readthedocs.io/) for getting usage examples and further informations.
