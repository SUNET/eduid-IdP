#!/usr/bin/python
#
# Copyright (c) 2014 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#

import six
import base64

from hashlib import sha256


def b64encode(source):
    # thank you https://stackoverflow.com/a/44688988
    if six.PY3:
        source = source.encode('utf-8')
    return base64.b64encode(source).decode('utf-8')


def maybe_xml_to_string(message, logger=None):
    """
    Try to parse message as an XML string, and then return it pretty-printed.

    If message couldn't be parsed, return string representation of it instead.

    This is used to (debug-)log SAML requests/responses in a readable way.

    :param message: XML string typically
    :param logger: logging logger
    :return: something ready for logging
    :rtype: string
    """
    try:
        from defusedxml import ElementTree as DefusedElementTree
        parser = DefusedElementTree.DefusedXMLParser()
        xml = DefusedElementTree.XML(str(message), parser)
        return DefusedElementTree.tostring(xml)
    except Exception as exc:
        if logger is not None:
            logger.debug("Could not parse message as XML: {!r}".format(exc))
        return str(message)


def generate_auth_token(shared_key, email, nonce, timestamp, generator=sha256):
    """
    The shared_key is a secret between the two systems
    """
    return generator("{0}|{1}|{2}|{3}".format(
        shared_key,
        email,
        nonce,
        timestamp,
    ).encode('utf-8')).hexdigest()
