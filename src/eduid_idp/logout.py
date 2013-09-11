#
# Copyright (c) 2013 NORDUnet A/S. All rights reserved.
# Copyright 2012 Roland Hedberg. All rights reserved.
#
# See the file eduid-IdP/LICENSE.txt for license statement.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#          Roland Hedberg
#

"""
Code handling Single Log Out requests.
"""
import pprint

from eduid_idp.service import Service
from eduid_idp.mischttp import Response, BadRequest, ServiceError, delete_cookie
import eduid_idp.mischttp

from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_SOAP

# -----------------------------------------------------------------------------
# === Single log out ===
# -----------------------------------------------------------------------------



class SLO(Service):

    def redirect(self):
        """ Expects a HTTP-redirect request """

        _dict = self.unpack_redirect()
        return self.perform_logout(_dict, BINDING_HTTP_REDIRECT)

    def post(self):
        """ Expects a HTTP-POST request """

        _dict = self.unpack_post()
        return self.perform_logout(_dict, BINDING_HTTP_POST)

    def soap(self):
        """
        Single log out using HTTP_SOAP binding
        """
        self.logger.debug("- SOAP -")
        _dict = self.unpack_soap()
        self.logger.debug("_dict: %s" % _dict)
        return self.perform_logout(_dict, BINDING_SOAP)

    def unpack_soap(self):
        try:
            # XXX suspect this is broken - get_post() returns a dict() now
            query = eduid_idp.mischttp.get_post(self.environ)
            return {"SAMLRequest": query, "RelayState": ""}
        except Exception:
            return None

    def perform_logout(self, _dict, binding):
        self.logger.info("--- Single Log Out Service ---")

        self.logger.debug("_perform_logout:\n{!s}".format(pprint.pformat(_dict)))
        if not _dict:
            resp = BadRequest('Error parsing request or no request')
            return resp(self.environ, self.start_response)

        request = _dict["SAMLRequest"]
        relay_state = _dict["RelayState"]

        try:
            _, body = request.split("\n")
            self.logger.debug("req: '%s'" % body)
            req_info = self.IDP.parse_logout_request(body, binding)
        except Exception, exc:
            self.logger.error("Bad request: %s" % exc)
            resp = BadRequest("%s" % exc)
            return resp(self.environ, self.start_response)

        msg = req_info.message
        if msg.name_id:
            _lid = self.IDP.ident.find_local_id(msg.name_id)
            _uid = self.IDP.cache.user2uid[_lid]
            self.logger.info("local identifier: {!s}".format(_lid))
            self.logger.debug("Purging from cache, uid : {!s}".format(self.IDP.cache.uid2user[_uid]))
            self.logger.debug("Purging from cache, lid : {!s}".format(self.IDP.cache.user2uid[_lid]))
            del self.IDP.cache.uid2user[_uid]
            del self.IDP.cache.user2uid[_lid]
            # remove the authentication
            try:
                self.IDP.session_db.remove_authn_statements(msg.name_id)
            except KeyError, exc:
                self.logger.error("ServiceError: %s" % exc)
                resp = ServiceError("%s" % exc)
                return resp(self.environ, self.start_response)

        resp = self.IDP.create_logout_response(msg, [binding])

        try:
            hinfo = self.IDP.apply_binding(binding, "%s" % resp, "", relay_state)
        except Exception, exc:
            self.logger.error("ServiceError: %s" % exc)
            resp = ServiceError("%s" % exc)
            return resp(self.environ, self.start_response)

        delco = delete_cookie("idpauthn", self.logger)
        if delco:
            hinfo["headers"].append(delco)
        self.logger.info("Header: %s" % (hinfo["headers"],))
        resp = Response(hinfo["data"], headers=hinfo["headers"])
        return resp(self.environ, self.start_response)
