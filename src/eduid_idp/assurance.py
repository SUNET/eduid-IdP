#!/usr/bin/python
#
# Copyright (c) 2013 NORDUnet A/S
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

"""
Assurance Level functionality.
"""

from saml2.authn_context import AuthnBroker
from saml2.authn_context import MOBILETWOFACTORCONTRACT
from saml2.authn_context import PASSWORD
from saml2.authn_context import PASSWORDPROTECTEDTRANSPORT
from saml2.authn_context import UNSPECIFIED
from saml2.authn_context import authn_context_class_ref
from saml2.authn_context import requested_authn_context

import eduid_idp.error

SWAMID_AL1 = 'http://www.swamid.se/policy/assurance/al1'
SWAMID_AL2 = 'http://www.swamid.se/policy/assurance/al2'
SWAMID_AL3 = 'http://www.swamid.se/policy/assurance/al3'

EDUID_INTERNAL_1_NAME = 'eduid.se:level:1'
EDUID_INTERNAL_2_NAME = 'eduid.se:level:2'
EDUID_INTERNAL_3_NAME = 'eduid.se:level:3'

EDUID_INTERNAL_1 = authn_context_class_ref(EDUID_INTERNAL_1_NAME)
EDUID_INTERNAL_2 = authn_context_class_ref(EDUID_INTERNAL_2_NAME)
EDUID_INTERNAL_3 = authn_context_class_ref(EDUID_INTERNAL_3_NAME)
EDUID_INTERNAL_UNSPECIFIED = authn_context_class_ref(UNSPECIFIED)

_context_to_internal = {
    'undefined': EDUID_INTERNAL_1,  # the default entry, used on unknown RequestedAuthnContext
    # Level 1
    SWAMID_AL1: EDUID_INTERNAL_1,
    PASSWORD: EDUID_INTERNAL_1,
    PASSWORDPROTECTEDTRANSPORT: EDUID_INTERNAL_1,
    UNSPECIFIED: EDUID_INTERNAL_1,
    # Level 2
    SWAMID_AL2: EDUID_INTERNAL_2,
    MOBILETWOFACTORCONTRACT: EDUID_INTERNAL_2,
    # Level 3
    SWAMID_AL3: EDUID_INTERNAL_3,
}

_response_translation = {
    EDUID_INTERNAL_1_NAME: SWAMID_AL1,
    EDUID_INTERNAL_2_NAME: SWAMID_AL2,
    EDUID_INTERNAL_3_NAME: SWAMID_AL3,
    PASSWORD: {
        EDUID_INTERNAL_1_NAME: SWAMID_AL1,
        EDUID_INTERNAL_2_NAME: SWAMID_AL2,
        EDUID_INTERNAL_3_NAME: SWAMID_AL3,
    },
    UNSPECIFIED: SWAMID_AL1,
}


def init_AuthnBroker(my_id):
    """
    Create and return a saml2 AuthnBroker.

    :param my_id: The IdP entity id as string
    :return: AuthnBroker instance
    """
    # NOTE: The function pointers supplied to the AUTHN_BROKER is not for authentication,
    # but for displaying proper login forms it seems. In eduid_idp, a single function
    # is used to display login screen regardless of Authn method, so a simple '1' is used
    # instead of the function pointer (has to evaulate to true).
    AUTHN_BROKER = AuthnBroker()
    AUTHN_BROKER.add(EDUID_INTERNAL_3, 1, 300, my_id, reference = EDUID_INTERNAL_3_NAME + ':300')
    AUTHN_BROKER.add(EDUID_INTERNAL_2, 1, 200, my_id, reference = EDUID_INTERNAL_2_NAME + ':200')
    AUTHN_BROKER.add(EDUID_INTERNAL_1, 1, 100, my_id, reference = EDUID_INTERNAL_1_NAME + ':100')
    AUTHN_BROKER.add(EDUID_INTERNAL_UNSPECIFIED, "", 0, my_id, reference = "eduid.se:level:unspecified")
    return AUTHN_BROKER


def canonical_req_authn_context(req_authn_ctx, logger, contexts=_context_to_internal):
    """
    Return internal representation (canonical form) of RequestedAuthnContext requested by SP.

    :param req_authn_ctx: saml2.samlp.RequestedAuthnContext instance
    :param logger: logging logger
    :param contexts: context class_ref lookup table (dict)
    :return: saml2.samlp.RequestedAuthnContext instance
    """
    try:
        class_ref = req_authn_ctx.authn_context_class_ref[0].text
    except AttributeError:
        class_ref = None
    if class_ref is None or class_ref not in contexts:
        if 'undefined' not in contexts:
            logger.debug("Can't canonicalize unknown AuthnContext : {!r}".format(class_ref))
            return None
        new_ctx = contexts['undefined']
    else:
        new_ctx = contexts[class_ref]

    # turn AuthnContext() into RequestedAuthnContext()
    new_class_ref = new_ctx.authn_context_class_ref.text
    new_req_authn_ctx = requested_authn_context(new_class_ref)
    logger.debug("Translated AuthnContext {!r} to {!r} ({!r})".format(
        class_ref, new_class_ref, new_req_authn_ctx))
    return new_req_authn_ctx


def response_authn(req_authn_ctx, actual_authn, auth_levels, logger, response_contexts=_response_translation):
    """
    Figure out what AuthnContext to assert in a SAML response,
    given the RequestedAuthnContext from the SAML request.

    :param req_authn_ctx: saml2.samlp.RequestedAuthnContext instance
    :param actual_authn: dict with information about the authenticated context
    :param auth_levels: list with class_ref strings OK for req_authn_ctx
    :param logger: logging logger
    :param response_contexts: response context class_ref lookup table (dict)
    :return: dict with information about the authn context (pysaml2 style)
    """
    # Start out with result template (res) based only on the actual authentication performed
    if actual_authn['class_ref'] not in response_contexts:
        logger.error("Failed looking up baseline response AuthnContext for authentication class {!r}".format(
            actual_authn['class_ref']))
        raise eduid_idp.error.ServiceError("Server assurance level configuration error", logger)
    res = {
        'class_ref': response_contexts[actual_authn['class_ref']],
        'authn_auth': actual_authn['authn_auth'],
    }

    try:
        req_class_ref = req_authn_ctx.authn_context_class_ref[0].text
    except AttributeError:
        req_class_ref = None

    lowered = actual_authn['class_ref'] not in auth_levels
    if lowered or req_class_ref is None:
        if req_class_ref is not None:
            logger.debug('Lowered authentication detected, {!r} required {!r}, got {!r}'.format(
                req_class_ref, auth_levels, actual_authn['class_ref']))
        logger.debug('Response Authn: Asserting AuthnContext {!r} based on authentication level ({!r})'.format(
            res['class_ref'], actual_authn['class_ref']))
        return res

    if req_class_ref not in response_contexts:
        res['class_ref'] = req_class_ref
        logger.debug('Response Authn: Asserting requested AuthnContext {!r} (no translation available)'.format(
            res['class_ref']))
        return res

    # The entrys in response_contexts are either 1-to-1 mappings of class_ref,
    # or dicts expressing different response authns for this req_authn_ctx at different
    # canonical levels (the internal EDUID_INTERNAL_n levels).
    try:
        new_class_ref = response_contexts[req_class_ref][actual_authn['class_ref']]
        logger.debug('Translated class_ref {!r} to {!r} from internal authn level {!r}'.format(
            req_class_ref, new_class_ref, actual_authn['class_ref']))
    except (KeyError, TypeError):
        new_class_ref = response_contexts[req_class_ref]  # can't fail, checked 'in' above
        logger.debug('Translated response AuthnContext class_ref {!r} to {!r}'.format(
            req_class_ref, new_class_ref))

    res['class_ref'] = new_class_ref
    return res