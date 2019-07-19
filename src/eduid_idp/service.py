#
# Copyright (c) 2013, 2014 NORDUnet A/S
# Copyright 2012 Roland Hedberg. All rights reserved.
# All rights reserved.
#
# See the file eduid-IdP/LICENSE.txt for license statement.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#          Roland Hedberg
#

"""
Common code for SSO login/logout requests.
"""

from typing import Callable

import eduid_idp.mischttp
from eduid_idp.context import IdPContext
from eduid_common.session.sso_session import SSOSession


class Service(object):
    """
    Base service class. Common code for SSO and SLO classes.

    :param session: SSO session
    :param start_response: WSGI-like start_response function pointer
    :param context: IdP context
    """

    def __init__(self, sso_session: SSOSession,
                 start_response: Callable, context: IdPContext):
        self.context = context
        self.start_response = start_response
        self.sso_session = sso_session
        # TODO: Get rid of this copying of things in the context
        self.logger = context.logger
        self.config = context.config

    def unpack_redirect(self):
        """
        Unpack redirect (GET) parameters.

        :return: query parameters as dict
        :rtype: dict
        """
        return eduid_idp.mischttp.parse_query_string(self.logger)

    def unpack_post(self):
        """
        Unpack POSTed parameters.

        :return: query parameters as dict
        :rtype: dict
        """
        info = eduid_idp.mischttp.get_post(self.logger)
        self.logger.debug("unpack_post:: %s" % info)
        try:
            return dict([(k, v) for k, v in info.items()])
        except AttributeError:
            return None

    def unpack_either(self):
        """
        Unpack either redirect (GET) or POST parameters.

        :return: query parameters as dict
        :rtype: dict or None
        """
        method = eduid_idp.mischttp.get_http_method()
        if method == 'GET':
            _dict = self.unpack_redirect()
        elif method == 'POST':
            _dict = self.unpack_post()
        else:
            _dict = None
        self.logger.debug("Unpacked {!r}, _dict: {!s}".format(method, _dict))
        return _dict

    def redirect(self):
        """ Expects a HTTP-redirect request """
        raise NotImplementedError('Subclass should implement function "redirect"')

    def post(self):
        """ Expects a HTTP-POST request """
        raise NotImplementedError('Subclass should implement function "post"')
