#!/usr/bin/python
#
# Copyright (c) 2013, 2014 NORDUnet A/S
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


import pprint

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

# Default set of canonicalizations for authentication contexts
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

# Rules deciding what AuthnContext to put in SAML responses

# This dict is for the ones that should actually be translated into something else.
#   Two-level has precedence, so for PASSWORD the response will be
#   SWAMID_AL1 for anything found to be equivalent of EDUID_INTERNAL_1
#   and so on.
_response_translation = {
    SWAMID_AL1: SWAMID_AL1,
    SWAMID_AL2: SWAMID_AL2,
    SWAMID_AL3: SWAMID_AL3,
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

    :type my_id: string
    :rtype: AuthnBroker
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

    :param req_authn_ctx: RequestedAuthnContext from SAML request
    :param logger: logging logger
    :param contexts: context class_ref lookup table (dict)
    :return: Canonical RequestedAuthnContext

    :type req_authn_ctx: saml2.samlp.RequestedAuthnContext
    :type logger: logging.Logger
    :type contexts: dict
    :rtype: saml2.samlp.RequestedAuthnContext
    """
    try:
        class_ref = req_authn_ctx.authn_context_class_ref[0].text
    except AttributeError:
        class_ref = None

    new_ctx = _canonical_ctx(class_ref, contexts, logger)
    if new_ctx is None:
        return None

    # turn AuthnContext() into RequestedAuthnContext()
    new_class_ref = new_ctx.authn_context_class_ref.text
    new_req_authn_ctx = requested_authn_context(new_class_ref)
    logger.debug("Translated AuthnContext {!r} to {!r} ({!r})".format(
        class_ref, new_class_ref, new_req_authn_ctx))
    return new_req_authn_ctx


def response_authn(req_authn_ctx, actual_authn, auth_levels, logger,
                   response_contexts=_response_translation,
                   contexts=_context_to_internal):
    """
    Figure out what AuthnContext to assert in a SAML response,
    given the RequestedAuthnContext from the SAML request.

    Rules:

      If no AuthnContext is requested, the `undefined' entry in contexts will be used - if present.

      For unknown class_refs, eduID responds with the SWAMID URN for the authentication level performed.

      Some class_refs are known, but have no translation and are returned as requested (the ones that
      can be canonicalized through contexts, but are not present in response_contexts).

      Some class_refs are known to eduID and are translated into something (the ones in response_contexts).


    :param req_authn_ctx: saml2.samlp.RequestedAuthnContext instance
    :param actual_authn: information about the authenticated context
    :param auth_levels: list with class_ref strings OK for req_authn_ctx
    :param logger: logging logger
    :param response_contexts: response context class_ref lookup table
    :param contexts: context class_ref lookup table (dict)
    :return: dict with information about the authn context (pysaml2 style)

    :type req_authn_ctx: saml2.samlp.RequestedAuthnContext
    :type actual_authn: dict
    :type auth_levels: list[string]
    :type logger: logging.Logger
    :type response_contexts: dict
    :type contexts: dict
    :rtype: dict
    """
    if actual_authn['class_ref'] not in response_contexts:
        logger.error("Failed looking up baseline response AuthnContext for authentication class {!r}".format(
            actual_authn['class_ref']))
        raise eduid_idp.error.ServiceError("Server assurance level configuration error", logger)

    try:
        req_class_ref = req_authn_ctx.authn_context_class_ref[0].text
    except AttributeError:
        req_class_ref = None

    if req_class_ref is None:
        # No requested AuthnContext, respond based on authentication level
        return _rewrite_authn_for_response(actual_authn, logger, None, response_contexts)

    if actual_authn['class_ref'] not in auth_levels:
        logger.warning('Too weak authentication detected, {!r} required {!r}, got {!r}'.format(
            req_class_ref, auth_levels, actual_authn['class_ref']))
        # XXX should return a login failure SAML response here, or maybe raise MustAuthenticate
        raise eduid_idp.error.Forbidden("Authn not permitted".format())

    if req_class_ref not in response_contexts:
        canonicalized = _canonical_ctx(req_class_ref, contexts, logger, use_default=False)
        if canonicalized is not None:
            res = _rewrite_authn_for_response(actual_authn, logger, req_class_ref, response_contexts)
            logger.debug('Response Authn: Returning requested AuthnContext {!r} (canonical: {!r})'.format(
                res['class_ref'], canonicalized.authn_context_class_ref.text))
            return res

        res = _rewrite_authn_for_response(actual_authn, logger, None, response_contexts)
        logger.debug('Response Authn: Returning auth-level AuthnContext {!r} (no translation available)'.format(
            res['class_ref']))
        return res

    return _rewrite_authn_for_response(actual_authn, logger, req_class_ref, response_contexts)


def _rewrite_authn_for_response(actual_authn, logger, req_class_ref, response_contexts):
    """
    Figure out what AuthnContext to put in the SAML response.

    :param actual_authn: information about the authenticated context
    :param logger: logging logger
    :param req_class_ref: requested AuthnContext
    :param response_contexts: response context class_ref lookup table
    :return: dict with information about the authn context (pysaml2 style)

    :type actual_authn: dict
    :type logger: logging.Logger
    :type req_class_ref: AuthnContext or None
    :type response_contexts: dict
    :rtype: dict
    """
    # Start out with result template (res) based only on the actual authentication performed
    res = {
        'class_ref': response_contexts[actual_authn['class_ref']],
        'authn_auth': actual_authn['authn_auth'],
    }

    authn_class_ref = actual_authn['class_ref']

    if req_class_ref is None:
        # No specific AuthnContext was requested by the SP
        logger.debug('Response Authn: Returning AuthnContext {!r} based on authentication level ({!r})'.format(
            res['class_ref'], authn_class_ref))
        return res

    if req_class_ref not in response_contexts:
        new_class_ref = req_class_ref
    else:
        this = response_contexts[req_class_ref]
        if isinstance(this, dict):
            try:
                this = this[authn_class_ref]
            except KeyError:
                logger.warning("Authn level {!r} not present in {!r} response-map".format(
                    authn_class_ref, req_class_ref))
                # fall back to authentication level
                return res
        new_class_ref = this

    res['class_ref'] = new_class_ref
    return res


def permitted_authn(user, authn, logger, contexts=_context_to_internal):
    """
    Decide if the IdP allows asserting authn for a user.

    :param user: User object
    :param authn: Result of response_authn above
    :param logger: Logging logger
    :param contexts: context class_ref lookup table
    :return: True on success

    :type user: IdPUser
    :type authn: dict
    :type logger: logging.Logger
    :type contexts: dict
    :rtype: bool
    """
    internal_class_ref = _canonical_ctx(authn['class_ref'], contexts, logger)
    if internal_class_ref == EDUID_INTERNAL_2:
        _verified_nins = [x for x in user.nins.to_list() if x.is_verified]
        if _verified_nins:
            logger.debug('Asserting AL2 based on {!r} verified norEduPersonNIN attribute'.format(
                len(_verified_nins)))
            return True
        else:
            logger.debug('NOT asserting AL2, no verified NINs: {!r}'.format(user.nins.to_list()))
            raise eduid_idp.error.Forbidden("The SP requires AuthnContext {!r} (AL2)".format(authn['class_ref']))
    elif internal_class_ref == EDUID_INTERNAL_1:
        return True
    logger.error('Id-proofing Authn rules not defined for internal level {!r}'.format(internal_class_ref))
    return False


def _canonical_ctx(class_ref, contexts, logger, use_default=True):
    """
    Return canonical context given a class_ref (string).

    :param class_ref: String, e.g. 'http://www.swamid.se/policy/assurance/al1' or None
    :param contexts: Dict with contexts
    :param logger: logging logger
    :return: AuthnContext from `contexts'

    :type class_ref: string or None
    :type logger: logging.Logger
    :type contexts: dict
    :rtype: saml2.samlp.AuthnContext
    """
    if class_ref is None or class_ref not in contexts:
        if not use_default:
            return None
        if 'undefined' not in contexts:
            logger.warning("Can't canonicalize unknown AuthnContext: {!r}".format(class_ref))
            return None
        new_ctx = contexts['undefined']
        logger.debug('Using default AuthnContext {!r}, {!r} not in contexts:\n{!s}'.format(
            new_ctx.authn_context_class_ref.text, class_ref, pprint.pformat(contexts)
        ))
    else:
        new_ctx = contexts[class_ref]
    return new_ctx


def get_authn_context(broker, ref, class_ref=None, logger=None):
    """
    Look up an authentication context by reference.

    :param broker: pysaml2 AuthnBroker
    :param ref: AuthnBroker opaque reference
    :param class_ref: Expected Authn class ref as string
    :param logger: logging logger
    :return: authn context or None

    :type broker: AuthnBroker
    :type ref: object
    :type class_ref: string | None
    :rtype: dict | None | False
    """
    try:
        _authn = broker[ref]
        if class_ref is not None:
            if _authn['class_ref'] != class_ref:
                if logger:
                    logger.warning("AuthN context returned for ref {!r} class_ref mismatch".format(ref))
                    logger.debug("Got AuthN context class_ref {!r}, expected {!r}".format(
                        _authn['class_ref'], class_ref))
                return False
        return _authn
    except KeyError:
        if logger:
            logger.warning("No AuthN context found using ref {!r}".format(ref))
