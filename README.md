# oidcmsg
Implementation of OIDC protocol messages.

oidcmsg is the 2nd layer in the
JwtConnect stack (cryptojwt, oidcmsg, oidcservice, oidcrp)

Handles serialising into a couple of formats (jwt, json, urlencoded and dict) and deserialising from said formats.

It also does verification of messages , that is :

+ does all the required parameters have a value
+ are the parameter values of the right type
+ if there is a list of permitted values is a parameter value in that list.

Also implements a **KeyJar** which keeps keys belonging to 
different owners. One owner may have many keys.
If some of these keys have a common origin, like described in a JWKS.
Such a set will be kept in a **keyBundle**.
Also implemented in this package. 
   
