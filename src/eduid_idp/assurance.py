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

class MissingSingleFactor(Exception):
    pass

class MissingMultiFactor(Exception):
    pass

class MissingAuthentication(Exception):
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
        self.u2f_used = False
        self._creds = []

        for this in sso_session.authn_credentials:
            cred = user.credentials.find(this['cred_id'])
            self.logger.debug('Adding used credential: {}'.format(cred))
            self._creds += [this]
            # until we can go to Python3 and have some... working type checks please
            if 'Password' in str(cred):
                self.password_used = True
            elif 'U2F' in str(cred):
                self.u2f_used = True

        self.is_swamid_al2 = False
        if user.nins.verified.to_list():
            self.is_swamid_al2 = True


    @property
    def is_singlefactor(self):
        return self.password_used or self.u2f_used

    @property
    def is_multifactor(self):
        return self.password_used and self.u2f_used

    @property
    def is_swamid_mfa_hi(self):
        if not self.is_swamid_al2:
            return False
        # XXX look through self._creds to see if there is any 'MFA-HI' tokens there
        return False


def response_authn(req_authn_ctx, user, sso_session, logger):
    """
    Figure out what AuthnContext to assert in a SAML response,
    given the RequestedAuthnContext from the SAML request.

    :param req_authn_ctx: Requested authn context class
    :param logger: logging logger
    :return: dict with information about the authn context (pysaml2 style)

    :type req_authn_ctx: str
    :type user: eduid_idp.idp_user.IdPUser
    :type sso_session: eduid_idp.sso_session.SSOSession
    :type logger: logging.Logger
    :rtype: str | None
    """
    authn = AuthnState(user, sso_session, logger)

    cc = {'REFEDS_MFA':  'https://refeds.org/profile/mfa',
          'REFEDS_SFA':  'https://refeds.org/profile/sfa',
          'FIDO_U2F':    'https://fidoalliance.org/specs/id-fido-u2f-ce-transports',
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
        response_authn = cc['REFEDS_MFA']

    elif req_authn_ctx == cc['REFEDS_SFA']:
        if not authn.is_singlefactor:
            raise MissingSingleFactor()
        response_authn = cc['REFEDS_SFA']

    elif req_authn_ctx == cc['FIDO_U2F']:
        if not authn.password_used and authn.u2f_used:
            raise MissingMultiFactor()
        response_authn = cc['FIDO_U2F']

    elif req_authn_ctx == cc['PASSWORD_PT']:
        if authn.password_used:
            response_authn = cc['PASSWORD_PT']

    else:
        # Handle both unknown and empty req_authn_ctx the same
        if authn.password_used and authn.u2f_used:
            response_authn = cc['FIDO_U2F']
        elif authn.password_used:
            response_authn = cc['PASSWORD_PT']

    if not response_authn:
        raise MissingAuthentication()

    if authn.is_swamid_mfa_hi and req_authn_ctx in [cc['REFEDS_SFA'], cc['REFEDS_MFA']]:
        attributes['eduPersonAssurance'] = [SWAMID_AL1, SWAMID_AL2, SWAMID_AL2_MFA_HI]
    elif authn.is_swamid_al2:
        attributes['eduPersonAssurance'] = [SWAMID_AL1, SWAMID_AL2]
    else:
        attributes['eduPersonAssurance'] = [SWAMID_AL1]

    return response_authn, attributes
