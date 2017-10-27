.. _oicmsg_howto:

How to use the oicmsg Message class
***********************************

Basic usage
-----------

An oicmsg :py:class:`oicmsg.message.Message instance` instance have some
functionality common with Python dictionaries.
So you can do things like assign values to a key::

    >>> from oicmsg.message import Message
    >>> msg = Message()
    >>> msg['key'] = 'value'

And you can read a value assigned to a key::

    >>> from oicmsg.message import Message
    >>> msg = Message()
    >>> msg['key'] = 'value'
    >>> val = msg['key']
    >>> print(val)
    'value'

:py:class:`oicmsg.message.Message instance` also supports other dictionary
methods::

    >>> from oicmsg.message import Message
    >>> msg = Message()
    >>> msg['key'] = 'value'
