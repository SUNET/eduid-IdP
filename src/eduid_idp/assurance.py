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
import logging
from typing import List, Optional

from eduid_common.authn.idp_saml import AuthnInfo
from eduid_common.idp.user import IdPUser
from eduid_userdb.credentials import Credential, METHOD_SWAMID_AL2_MFA, METHOD_SWAMID_AL2_MFA_HI

"""
Assurance Level functionality.
"""


class AssuranceException(Exception):
    pass


class MissingSingleFactor(AssuranceException):
    pass


class MissingMultiFactor(AssuranceException):
    pass


class WrongMultiFactor(AssuranceException):
    pass


class MissingAuthentication(AssuranceException):
    pass


class AuthnState(object):

    def __init__(self, user, sso_session, logger):
        """

        :param user:
        :param sso_session:

        :type user: eduid_idp.idp_user.IdPUser
        :type sso_session: eduid_idp.sso_session.SSOSession
        """
        self.logger = logger

        # authn_credentials is a list of dicts created by AuthnData.to_session_dict(), e.g.:
        # {'cred_id': self.credential.key,
        #  'authn_ts': self.timestamp,
        # }
        self.password_used = False
        self.is_swamid_al2 = False
        self.fido_used = False
        self.external_mfa_used = False
        self.swamid_al2_used = False
        self.swamid_al2_hi_used = False
        self._creds: List[Credential] = []

        for this in sso_session.authn_credentials:
            cred = user.credentials.find(this['cred_id'])
            if not cred:
                self.logger.warning('Could not find credential {!r} on user {}'.format(this['cred_id'], user))
                continue
            self.logger.debug('Adding used credential: {}'.format(cred))
            self._creds += [cred]
            # until we can go to Python3 and have some... working type checks please
            if 'Password' in str(cred):
                self.password_used = True
            elif 'U2F' in str(cred) or 'Webauthn' in str(cred):
                # TODO: Match this using eduid_credential.credentials.FidoCredential instead, if that works
                #       now that we use Python 3
                self.fido_used = True

        if self.password_used:
            # second pass for second factor
            for cred in [x for x in self._creds if 'Password' not in str(x)]:
                if cred.is_verified:
                    if cred.proofing_method == METHOD_SWAMID_AL2_MFA:
                        self.swamid_al2_used = True
                    elif cred.proofing_method == METHOD_SWAMID_AL2_MFA_HI:
                        self.swamid_al2_hi_used = True
            # External mfa check
            if sso_session.external_mfa is not None:
                self.logger.debug('External MFA issuer: {}'.format(sso_session.external_mfa.issuer))
                self.external_mfa_used = True
                # TODO: Support more SwedenConnect authn contexts?
                if sso_session.external_mfa.authn_context == 'http://id.elegnamnden.se/loa/1.0/loa3':
                    self.swamid_al2_hi_used = True

        if user.nins.verified.to_list():
            self.is_swamid_al2 = True

    def __str__(self):
        return (f'<AuthnState: creds={len(self._creds)}, pw={self.password_used}, fido={self.fido_used}, '
                f'external_mfa={self.external_mfa_used}, nin is al2={self.is_swamid_al2}, '
                f'mfa is (al2={self.swamid_al2_used}, al2_hi={self.swamid_al2_hi_used})>')

    @property
    def is_singlefactor(self):
        return self.password_used or self.fido_used

    @property
    def is_multifactor(self):
        return self.password_used and (self.fido_used or self.external_mfa_used)

    @property
    def is_swamid_al2_mfa(self):
        return self.swamid_al2_used or self.swamid_al2_hi_used


# Can't type sso_session: SSOSession here because it creates an import dependency loop
def response_authn(req_authn_ctx: Optional[str], user: IdPUser, sso_session, logger: logging.Logger) -> AuthnInfo:
    """
    Figure out what AuthnContext to assert in a SAML response,
    given the RequestedAuthnContext from the SAML request.

    :param req_authn_ctx: Requested authn context class
    """
    authn = AuthnState(user, sso_session, logger)
    logger.info(f'Authn for {user} will be evaluated based on: {authn}')

    cc = {'REFEDS_MFA':  'https://refeds.org/profile/mfa',
          'REFEDS_SFA':  'https://refeds.org/profile/sfa',
          'FIDO_U2F':    'https://www.swamid.se/specs/id-fido-u2f-ce-transports',
          'PASSWORD_PT': 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
          }

    SWAMID_AL1 = 'http://www.swamid.se/policy/assurance/al1'
    SWAMID_AL2 = 'http://www.swamid.se/policy/assurance/al2'
    SWAMID_AL2_MFA_HI = 'http://www.swamid.se/policy/authentication/swamid-al2-mfa-hi'

    attributes = {}
    response_authn = None

    if req_authn_ctx == cc['REFEDS_MFA']:
        if not authn.is_multifactor:
            raise MissingMultiFactor()
        if not authn.is_swamid_al2_mfa:
            raise WrongMultiFactor()
        response_authn = cc['REFEDS_MFA']

    elif req_authn_ctx == cc['REFEDS_SFA']:
        if not authn.is_singlefactor:
            raise MissingSingleFactor()
        response_authn = cc['REFEDS_SFA']

    elif req_authn_ctx == cc['FIDO_U2F']:
        if not authn.password_used and authn.fido_used:
            raise MissingMultiFactor()
        response_authn = cc['FIDO_U2F']

    elif req_authn_ctx == cc['PASSWORD_PT']:
        if authn.password_used:
            response_authn = cc['PASSWORD_PT']

    else:
        # Handle both unknown and empty req_authn_ctx the same
        if authn.password_used and authn.fido_used:
            response_authn = cc['FIDO_U2F']
        elif authn.password_used:
            response_authn = cc['PASSWORD_PT']

    if not response_authn:
        raise MissingAuthentication()

    if authn.is_swamid_al2:
        if authn.swamid_al2_hi_used and req_authn_ctx in [cc['REFEDS_SFA'], cc['REFEDS_MFA']]:
            attributes['eduPersonAssurance'] = [SWAMID_AL1, SWAMID_AL2, SWAMID_AL2_MFA_HI]
        else:
            attributes['eduPersonAssurance'] = [SWAMID_AL1, SWAMID_AL2]
    else:
        attributes['eduPersonAssurance'] = [SWAMID_AL1]

    logger.info(f'Assurances for {user} was evaluated to: {response_authn} with attributes {attributes}')
    return AuthnInfo(class_ref=response_authn, authn_attributes=attributes)
