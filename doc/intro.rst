.. _oicmsg_intro:

**********************
Introduction to oicmsg
**********************

The OpenID Connect and OAuth2 standards both defines lots of messages.
Requests that are sent from clients to servers and responses from servers
to clients.

For each of these messages a number of parameters (claims) are listed, some
of them required and some optional. Each parameter are also assigned data type.

What is also defined in the standard is the on-the-wire representation of
these messages. Like if they are the fragment component of a redirect URI or a
JSON document transferred in the body of a response.

The :py:class:`oicmsg.message.Message` class is supposed to capture all of this.

Using this class you should be able to:

    - build a message,
    - verify that a messages parameters are correct (all the required present
        and all of the right type)
    - serialize the message into the on-the-wire representation
    - deserialize a received message from the on-the-wire representation into
        a :py:class:`oicmsg.message.Message` instance.

I will try to walk you through these steps using example from RFC6749 (section
4.1 and 4.2).

Entity sending a message
------------------------

Going from a set of attributes with values how would you go about creating an
authorization request ? You would do something like this::

    from oicmsg.oauth2 import AuthorizationRequest

    request_parameters = {
        "response_type": "code",
        "client_id": "s6BhdRkqt3",
        "state": "xyz",
        "redirect_uri": "https://client.example.com/cb"
    }

    message = AuthorizationRequest(**request_parameters)

    authorization_endpoint = "https://server.example.com/authorize"

    authorization_request = message.request(authorization_endpoint)

The resulting request will look like this ::

    https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb


If we continue with the client sending an access token request there is a
pattern emerging::

    from oicmsg.oauth2 import AccessTokenRequest

    request = {
        'grant_type':'authorization_code',
        'code':'SplxlOBeZQQYbYS6WxSbIA',
        'redirect_uri':'https://client.example%2Ecom%2Fcb'
    }

    message = AccessTokenRequest(**request)

    access_token_request = message.to_urlencoded()

The resulting request will look like this::

    grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA&redirect_uri=https%3A%2F%2Fclient.example%252Ecom%252Fcb

Ready to be put in the HTTP POST body sent to the token endpoint.

The pattern is:

    1. Collect the parameters (with values) that are to appear in the request
    2. Chose the appropriate Message subclass
    3. Initiate the sub class with the collected information
    4. Serialize the message into whatever format is appropriate

Now, I have given examples on how a client would construct a request but of course
there is not difference between this and a server constructing a response.
The set of parameters is different and the message sub class to be used is
different but the process is the same.

Entity receiving a message
--------------------------

Now the other side of the coin. An entity receives a message from its opponent.
What to do ?

Again I'll start with an example and again we'll take the view of the client.
The client has sent an authorization request, the user has been redirected to
authenticate and decide on what permissions to grant and finally the server
has redirect the user-agent back to the client by sending the HTTP response::

    https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz

On the client it would get hold of the query part and then go from there::

    from oicmsg.oauth2 import AuthorizationResponse

    query_conponent = 'code=SplxlOBeZQQYbYS6WxSbIA&state=xyz'

    response = AuthorizationResponse().from_urlencoded(query_conponent)

    print(response.verify())
    print(response)

The result of this will be::

    True
    {'code': 'SplxlOBeZQQYbYS6WxSbIA', 'state': 'xyz'}

Similar when it comes to the response from the token endpoint::

    from oicmsg.oauth2 import AccessTokenResponse

    http_response_body = '{"access_token":"2YotnFZFEjr1zCsicMWpAA",' \
                     '"token_type":"example","expires_in":3600,' \
                     '"refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",' \
                     '"example_parameter":"example_value"}'

    response = AccessTokenResponse().from_json(http_response_body)

    print(response.verify())
    print(response)

and this time the result will be::

    True
    {'access_token': '2YotnFZFEjr1zCsicMWpAA', 'token_type': 'example', 'expires_in': 3600, 'refresh_token': 'tGzv3JOkF0XG5Qx2TlKWIA', 'example_parameter': 'example_value'}

The processing pattern on the receiving end is:

    1. Pick out the protocol message part of the response
    2. Initiate the correct message subclass and run the appropriate
        deserializer method.
    3. Verify the correctness of the response


