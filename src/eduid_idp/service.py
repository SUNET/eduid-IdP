#
# Copyright (c) 2013 NORDUnet A/S
# Copyright 2012 Roland Hedberg. All rights reserved.
# All rights reserved.
#
# See the file eduid-IdP/LICENSE.txt for license statement.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#          Roland Hedberg
#

"""
Code handling Single Sign On logins.
"""

import pprint

import eduid_idp.mischttp
from eduid_idp.mischttp import Response, BadRequest, Redirect

from saml2 import BINDING_HTTP_ARTIFACT
from saml2 import BINDING_SOAP
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST

class Service(object):

    def __init__(self, environ, start_response, idp_app, user=None):
        self.environ = environ
        idp_app.logger.debug("ENVIRON:\n{!s}".format(pprint.pformat(environ)))
        self.start_response = start_response
        self.logger = idp_app.logger
        self.IDP = idp_app.IDP
        self.AUTHN_BROKER = idp_app.AUTHN_BROKER
        self.config = idp_app.config
        self.user = user

    def unpack_redirect(self):
        return eduid_idp.mischttp.parse_query_string()

    def unpack_post(self):
        #_dict = parse_qs(get_post(self.environ))
        _dict = eduid_idp.mischttp.get_post()
        self.logger.debug("unpack_post:: %s" % _dict)
        try:
            return dict([(k, v) for k, v in _dict.items()])
        except Exception:
            return None

    def unpack_soap(self):
        try:
            # XXX suspect this is broken - get_post() returns a dict() now
            query = eduid_idp.mischttp.get_post(self.environ)
            return {"SAMLRequest": query, "RelayState": ""}
        except Exception:
            return None

    def unpack_either(self):
        if self.environ["REQUEST_METHOD"] == "GET":
            _dict = self.unpack_redirect()
        elif self.environ["REQUEST_METHOD"] == "POST":
            _dict = self.unpack_post()
        else:
            _dict = None
        self.logger.debug("_dict: %s" % _dict)
        return _dict

    def operation(self, _dict, binding):
        self.logger.debug("_operation:\n{!s}".format(pprint.pformat(_dict)))
        if not _dict:
            resp = BadRequest('Error parsing request or no request')
            return resp(self.environ, self.start_response)
        else:
            return self.do(_dict["SAMLRequest"], binding, _dict["RelayState"])

    def artifact_operation(self, _dict):
        if not _dict:
            resp = BadRequest("Missing query")
            return resp(self.environ, self.start_response)
        else:
            # exchange artifact for request
            request = self.IDP.artifact2message(_dict["SAMLart"], "spsso")
            return self.do(request, BINDING_HTTP_ARTIFACT, _dict["RelayState"])

    def response(self, binding, http_args):
        if binding == BINDING_HTTP_ARTIFACT:
            resp = Redirect()
        else:
            resp = Response(http_args["data"], headers=http_args["headers"])
        return resp(self.environ, self.start_response)

    def do(self, query, binding, relay_state=""):
        raise NotImplementedError('Subclass should implement function "do"')

    def redirect(self):
        """ Expects a HTTP-redirect request """

        _dict = self.unpack_redirect()
        return self.operation(_dict, BINDING_HTTP_REDIRECT)

    def post(self):
        """ Expects a HTTP-POST request """

        _dict = self.unpack_post()
        return self.operation(_dict, BINDING_HTTP_POST)

    def artifact(self):
        # Can be either by HTTP_Redirect or HTTP_POST
        _dict = self.unpack_either()
        return self.artifact_operation(_dict)

    def soap(self):
        """
        Single log out using HTTP_SOAP binding
        """
        self.logger.debug("- SOAP -")
        _dict = self.unpack_soap()
        self.logger.debug("_dict: %s" % _dict)
        return self.operation(_dict, BINDING_SOAP)

    def uri(self):
        _dict = self.unpack_either()
        return self.operation(_dict, BINDING_SOAP)
