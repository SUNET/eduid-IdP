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
import base64
from logging import Logger
from typing import Optional

import six
from eduid_common.authn.idp_saml import IdP_SAMLRequest
from saml2.server import Server as Saml2Server


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
    if isinstance(message, six.binary_type):
        # message is returned as binary from pysaml2 in python3
        message = message.decode('utf-8')
    message = str(message)
    try:
        from defusedxml import ElementTree as DefusedElementTree

        parser = DefusedElementTree.DefusedXMLParser()
        xml = DefusedElementTree.XML(message, parser)
        return DefusedElementTree.tostring(xml)
    except Exception as exc:
        if logger is not None:
            logger.debug("Could not parse message of type {!r} as XML: {!r}".format(type(message), exc))
        return message


def get_requested_authn_context(idp: Saml2Server, saml_req: IdP_SAMLRequest, logger: Logger) -> Optional[str]:
    """
    Check if the SP has explicit Authn preferences in the metadata (some SPs are not
    capable of conveying this preference in the RequestedAuthnContext)
    """
    res = saml_req.get_requested_authn_context()

    attributes = saml_req.sp_entity_attributes

    if 'http://www.swamid.se/assurance-requirement' in attributes:
        # XXX don't just pick the first one from the list - choose the most applicable one somehow.
        new_authn = attributes['http://www.swamid.se/assurance-requirement'][0]
        logger.debug(
            f'Entity {saml_req.sp_entity_id} has AuthnCtx preferences in metadata. ' f'Overriding {res} -> {new_authn}'
        )
        res = new_authn

    return res
