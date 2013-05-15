#!/usr/bin/env python

import os
import re
import sys
import time
import base64
import logging
import argparse
from hashlib import sha1

import cherrypy
import cherrypy.wsgiserver

import eduid_idp

from urlparse import parse_qs
from Cookie import SimpleCookie

from saml2 import server
from saml2 import BINDING_HTTP_ARTIFACT
from saml2 import BINDING_URI
from saml2 import BINDING_PAOS
from saml2 import BINDING_SOAP
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2 import time_util

from saml2.authn_context import AuthnBroker
from saml2.authn_context import PASSWORD
from saml2.authn_context import UNSPECIFIED
from saml2.authn_context import authn_context_class_ref
from saml2.httputil import Response
from saml2.httputil import NotFound
from saml2.httputil import geturl
from saml2.httputil import get_post
from saml2.httputil import Redirect
from saml2.httputil import Unauthorized
from saml2.httputil import BadRequest
from saml2.httputil import ServiceError
from saml2.ident import Unknown
from saml2.s_utils import rndstr, exception_trace
from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding
from saml2.s_utils import PolicyError
from saml2.sigver import verify_redirect_signature

default_config_file = "/opt/eduid/conf/idp.ini"
default_debug = False


def parse_args():
    """
    Parse the command line arguments
    """
    parser = argparse.ArgumentParser(description = "eduID Identity Provider application",
                                     add_help = True,
                                     formatter_class = argparse.ArgumentDefaultsHelpFormatter,
                                     )
    parser.add_argument('-c', '--config-file',
                        dest='config_file',
                        default=default_config_file,
                        help='Config file',
                        metavar='PATH',
                        )

    parser.add_argument('--debug',
                        dest='debug',
                        action='store_true', default=default_debug,
                        help='Enable debug operation',
                        )

    return parser.parse_args()


class Cache(object):
    def __init__(self):
        self.user2uid = {}
        self.uid2user = {}


def _expiration(timeout, tformat="%a, %d-%b-%Y %H:%M:%S GMT"):
    """

    :param timeout:
    :param tformat:
    :return:
    """
    if timeout == "now":
        return time_util.instant(tformat)
    elif timeout == "dawn":
        return time.strftime(tformat, time.gmtime(0))
    else:
        # validity time should match lifetime of assertions
        return time_util.in_a_while(minutes=timeout, format=tformat)

# -----------------------------------------------------------------------------


class Service(object):

    def __init__(self, environ, start_response, idp_app, user=None):
        self.environ = environ
        idp_app.logger.debug("ENVIRON: %s" % environ)
        self.start_response = start_response
        self.logger = idp_app.logger
        self.IDP = idp_app.IDP
        self.AUTHN_BROKER = idp_app.AUTHN_BROKER
        self.config = idp_app.config
        self.user = user

    def unpack_redirect(self):
        if "QUERY_STRING" in self.environ:
            _qs = self.environ["QUERY_STRING"]
            return dict([(k, v[0]) for k, v in parse_qs(_qs).items()])
        else:
            return None

    def unpack_post(self):
        _dict = parse_qs(get_post(self.environ))
        self.logger.debug("unpack_post:: %s" % _dict)
        try:
            return dict([(k, v[0]) for k, v in _dict.items()])
        except Exception:
            return None

    def unpack_soap(self):
        try:
            query = get_post(self.environ)
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
        self.logger.debug("_operation: %s" % _dict)
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
        pass

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

    # def not_authn(self, key):
    #     """
    #
    #
    #     :return:
    #     """
    #     loc = "http://%s/login" % (self.environ["HTTP_HOST"])
    #     loc += "?%s" % urllib.urlencode({"came_from": self.environ[
    #         "PATH_INFO"], "key": key})
    #     headers = [('Content-Type', 'text/plain')]
    #
    #     logger.debug("location: %s" % loc)
    #     logger.debug("headers: %s" % headers)
    #
    #     resp = Redirect(loc, headers=headers)
    #
    #     return resp(self.environ, self.start_response)

    def not_authn(self, key, requested_authn_context):
        ruri = geturl(self.environ, query=False)
        return do_authentication(self.environ, self.start_response,
                                 self.logger, self.config, self.AUTHN_BROKER,
                                 authn_context=requested_authn_context,
                                 key=key, redirect_uri=ruri)


# -----------------------------------------------------------------------------

REPOZE_ID_EQUIVALENT = "uid"
FORM_SPEC = """<form name="myform" method="post" action="%s">
   <input type="hidden" name="SAMLResponse" value="%s" />
   <input type="hidden" name="RelayState" value="%s" />
</form>"""

# -----------------------------------------------------------------------------
# === Single log in ====
# -----------------------------------------------------------------------------


class AuthenticationNeeded(Exception):
    def __init__(self, authn_context=None, *args, **kwargs):
        Exception.__init__(*args, **kwargs)
        self.authn_context = authn_context


class SSO(Service):

    def __init__(self, environ, start_response, idp_app, user=None):
        Service.__init__(self, environ, start_response, idp_app, user)
        self.binding = ""
        self.response_bindings = None
        self.resp_args = {}
        self.binding_out = None
        self.destination = None
        self.req_info = None

    def verify_request(self, query, binding):
        """
        :param query: The SAML query, transport encoded
        :param binding: Which binding the query came in over
        """
        if not query:
            self.logger.info("Missing QUERY")
            resp = Unauthorized('Unknown user')
            return resp(self.environ, self.start_response)

        if not self.req_info:
            self.req_info = self.IDP.parse_authn_request(query, binding)

        self.logger.info("parsed OK")
        _authn_req = self.req_info.message
        self.logger.debug("%s" % _authn_req)

        self.binding_out, self.destination = self.IDP.pick_binding(
            "assertion_consumer_service",
            bindings=self.response_bindings,
            entity_id=_authn_req.issuer.text)

        self.logger.debug("Binding: %s, destination: %s" % (self.binding_out,
                                                       self.destination))

        resp_args = {}
        try:
            resp_args = self.IDP.response_args(_authn_req)
            _resp = None
        except UnknownPrincipal, excp:
            _resp = self.IDP.create_error_response(_authn_req.id,
                                              self.destination, excp)
        except UnsupportedBinding, excp:
            _resp = self.IDP.create_error_response(_authn_req.id,
                                              self.destination, excp)

        return resp_args, _resp

    def do(self, query, binding_in, relay_state=""):
        try:
            resp_args, _resp = self.verify_request(query, binding_in)
        except UnknownPrincipal, excp:
            self.logger.error("UnknownPrincipal: %s" % (excp,))
            resp = ServiceError("UnknownPrincipal: %s" % (excp,))
            return resp(self.environ, self.start_response)
        except UnsupportedBinding, excp:
            self.logger.error("UnsupportedBinding: %s" % (excp,))
            resp = ServiceError("UnsupportedBinding: %s" % (excp,))
            return resp(self.environ, self.start_response)

        if not _resp:
            identity = USERS[self.user]
            self.logger.info("Identity: %s" % (identity,))

            if REPOZE_ID_EQUIVALENT:
                identity[REPOZE_ID_EQUIVALENT] = self.user
            try:
                _resp = self.IDP.create_authn_response(
                    identity, userid=self.user,
                    authn=self.AUTHN_BROKER[self.environ["idp.authn_ref"]],
                    **resp_args)
            except Exception, excp:
                self.logger.error(exception_trace(excp))
                resp = ServiceError("Exception: %s" % (excp,))
                return resp(self.environ, self.start_response)

        self.logger.info("AuthNResponse: %s" % _resp)
        http_args = self.IDP.apply_binding(self.binding_out,
                                      "%s" % _resp, self.destination,
                                      relay_state, response=True)
        self.logger.debug("HTTPargs: %s" % http_args)
        return self.response(self.binding_out, http_args)

    def _store_request(self, _dict):
        self.logger.debug("_store_request: %s" % _dict)
        key = sha1(_dict["SAMLRequest"]).hexdigest()
        # store the AuthnRequest
        self.IDP.ticket[key] = _dict
        return key

    def redirect(self):
        """ This is the HTTP-redirect endpoint """
        self.logger.info("--- In SSO Redirect ---")
        _info = self.unpack_redirect()

        try:
            _info = self.IDP.ticket[_info["key"]]
            self.req_info = _info["req_info"]
            del self.IDP.ticket[_info["key"]]
        except KeyError:
            if not "SAMLRequest" in _info:
                resp = BadRequest("Missing SAMLRequest, please re-initiate login")
                return resp(self.environ, self.start_response)

            self.req_info = self.IDP.parse_authn_request(_info["SAMLRequest"],
                                                    BINDING_HTTP_REDIRECT)
            _req = self.req_info.message

            if "SigAlg" in _info and "Signature" in _info:  # Signed request
                issuer = _req.issuer.text
                _certs = self.IDP.metadata.certs(issuer, "any", "signing")
                verified_ok = False
                for cert in _certs:
                    if verify_redirect_signature(_info, cert):
                        verified_ok = True
                        break
                if not verified_ok:
                    resp = BadRequest("Message signature verification failure")
                    return resp(self.environ, self.start_response)

            if self.user:
                if _req.force_authn:
                    _info["req_info"] = self.req_info
                    key = self._store_request(_info)
                    return self.not_authn(key, _req.requested_authn_context)
                else:
                    return self.operation(_info, BINDING_HTTP_REDIRECT)
            else:
                _info["req_info"] = self.req_info
                key = self._store_request(_info)
                return self.not_authn(key, _req.requested_authn_context)
        else:
            return self.operation(_info, BINDING_HTTP_REDIRECT)

    def post(self):
        """
        The HTTP-Post endpoint
        """
        self.logger.info("--- In SSO POST ---")
        _info = self.unpack_either()
        self.req_info = self.IDP.parse_authn_request(
            _info["SAMLRequest"], BINDING_HTTP_POST)
        _req = self.req_info.message
        if self.user:
            if _req.force_authn:
                _info["req_info"] = self.req_info
                key = self._store_request(_info)
                return self.not_authn(key, _req.requested_authn_context)
            else:
                return self.operation(_info, BINDING_HTTP_POST)
        else:
            _info["req_info"] = self.req_info
            key = self._store_request(_info)
            return self.not_authn(key, _req.requested_authn_context)

    # def artifact(self):
    #     # Can be either by HTTP_Redirect or HTTP_POST
    #     _req = self._store_request(self.unpack_either())
    #     if isinstance(_req, basestring):
    #         return self.not_authn(_req)
    #     return self.artifact_operation(_req)

    def ecp(self):
        # The ECP interface
        self.logger.info("--- ECP SSO ---")
        resp = None

        try:
            authz_info = self.environ["HTTP_AUTHORIZATION"]
            if authz_info.startswith("Basic "):
                _info = base64.b64decode(authz_info[6:])
                self.logger.debug("Authz_info: %s" % _info)
                try:
                    (user, passwd) = _info.split(":")
                    if PASSWD[user] != passwd:
                        resp = Unauthorized()
                    self.user = user
                except ValueError:
                    resp = Unauthorized()
            else:
                resp = Unauthorized()
        except KeyError:
            resp = Unauthorized()

        if resp:
            return resp(self.environ, self.start_response)

        _dict = self.unpack_soap()
        self.response_bindings = [BINDING_PAOS]
        # Basic auth ?!
        return self.operation(_dict, BINDING_SOAP)

# -----------------------------------------------------------------------------
# === Authentication ====
# -----------------------------------------------------------------------------


def do_authentication(environ, start_response, logger, config, AUTHN_BROKER,
                      authn_context, key, redirect_uri):
    """
    Display the login form
    """
    logger.debug("Do authentication")
    auth_info = AUTHN_BROKER.pick(authn_context)

    if len(auth_info):
        method, reference = auth_info[0]
        logger.debug("Authn chosen: %s (ref=%s)" % (method, reference))
        return method(environ, start_response, reference, key, redirect_uri, logger, config)
    else:
        resp = Unauthorized("No usable authentication method")
        return resp(environ, start_response)


# -----------------------------------------------------------------------------

PASSWD = {"roland": "dianakra",
          "babs": "howes",
          "upper": "crust"}


def username_password_authn(environ, start_response, reference, key,
                            redirect_uri, logger, config):
    """
    Display the login form
    """
    logger.info("The login page")
    headers = []

    static_fn = static_filename(config, 'login.html')
    logger.debug("LOGIN FILENAME {!r}".format(static_fn))
    if static_fn:
        return static_file(environ, start_response, static_fn)

    resp = Response(mako_template="login.mako", template_lookup=LOOKUP,
                    headers=headers)

    argv = {
        "action": "/verify",
        "login": "",
        "password": "",
        "key": key,
        "authn_reference": reference,
        "redirect_uri": redirect_uri
    }
    logger.info("do_authentication argv: %s" % argv)
    return resp(environ, start_response, **argv)


def verify_username_and_password(dic):
    global PASSWD
    # verify username and password
    if PASSWD[dic["login"][0]] == dic["password"][0]:
        return True, dic["login"][0]
    else:
        return False, ""


def do_verify(environ, start_response, idp_app, _):
    query = parse_qs(get_post(environ))

    idp_app.logger.debug("do_verify: %s" % query)

    try:
        _ok, user = verify_username_and_password(query)
    except KeyError:
        _ok = False
        user = None

    if not _ok:
        resp = Unauthorized("Unknown user or wrong password")
    else:
        uid = rndstr(24)
        idp_app.IDP.cache.uid2user[uid] = user
        idp_app.IDP.cache.user2uid[user] = uid
        idp_app.logger.debug("Register %s under '%s'" % (user, uid))

        kaka = set_cookie("idpauthn", "/", idp_app.logger, uid, query["authn_reference"][0])

        lox = "%s?id=%s&key=%s" % (query["redirect_uri"][0], uid,
                                   query["key"][0])
        idp_app.logger.debug("Redirect => %s" % lox)
        resp = Redirect(lox, headers=[kaka], content="text/html")

    return resp(environ, start_response)


def not_found(environ, start_response):
    """Called if no URL matches."""
    resp = NotFound()
    return resp(environ, start_response)


# -----------------------------------------------------------------------------
# === Single log out ===
# -----------------------------------------------------------------------------

#def _subject_sp_info(req_info):
#    # look for the subject
#    subject = req_info.subject_id()
#    subject = subject.text.strip()
#    sp_entity_id = req_info.message.issuer.text.strip()
#    return subject, sp_entity_id

class SLO(Service):
    def do(self, request, binding, relay_state=""):
        self.logger.info("--- Single Log Out Service ---")
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
            lid = self.IDP.ident.find_local_id(msg.name_id)
            self.logger.info("local identifier: %s" % lid)
            del self.IDP.cache.uid2user[self.IDP.cache.user2uid[lid]]
            del self.IDP.cache.user2uid[lid]
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

        delco = delete_cookie(self.environ, "idpauthn", self.logger)
        if delco:
            hinfo["headers"].append(delco)
        self.logger.info("Header: %s" % (hinfo["headers"],))
        resp = Response(hinfo["data"], headers=hinfo["headers"])
        return resp(self.environ, self.start_response)

# ----------------------------------------------------------------------------
# Manage Name ID service
# ----------------------------------------------------------------------------


class NMI(Service):

    def do(self, query, binding, relay_state=""):
        self.logger.info("--- Manage Name ID Service ---")
        req = self.IDP.parse_manage_name_id_request(query, binding)
        request = req.message

        # Do the necessary stuff
        name_id = self.IDP.ident.handle_manage_name_id_request(
            request.name_id, request.new_id, request.new_encrypted_id,
            request.terminate)

        self.logger.debug("New NameID: %s" % name_id)

        _resp = self.IDP.create_manage_name_id_response(request)

        # It's using SOAP binding
        hinfo = self.IDP.apply_binding(BINDING_SOAP, "%s" % _resp, "",
                                  relay_state, response=True)

        resp = Response(hinfo["data"], headers=hinfo["headers"])
        return resp(self.environ, self.start_response)

# ----------------------------------------------------------------------------
# === Assertion ID request ===
# ----------------------------------------------------------------------------


# Only URI binding
class AIDR(Service):
    def do(self, aid, binding, relay_state=""):
        self.logger.info("--- Assertion ID Service ---")

        try:
            assertion = self.IDP.create_assertion_id_request_response(aid)
        except Unknown:
            resp = NotFound(aid)
            return resp(self.environ, self.start_response)

        hinfo = self.IDP.apply_binding(BINDING_URI, "%s" % assertion, response=True)

        self.logger.debug("HINFO: %s" % hinfo)
        resp = Response(hinfo["data"], headers=hinfo["headers"])
        return resp(self.environ, self.start_response)

    def operation(self, _dict, binding, **kwargs):
        self.logger.debug("_operation: %s" % _dict)
        if not _dict or "ID" not in _dict:
            resp = BadRequest('Error parsing request or no request')
            return resp(self.environ, self.start_response)

        return self.do(_dict["ID"], binding, **kwargs)


# ----------------------------------------------------------------------------
# === Artifact resolve service ===
# ----------------------------------------------------------------------------

class ARS(Service):
    def do(self, request, binding, relay_state=""):
        _req = self.IDP.parse_artifact_resolve(request, binding)

        msg = self.IDP.create_artifact_response(_req, _req.artifact.text)

        hinfo = self.IDP.apply_binding(BINDING_SOAP, "%s" % msg, "", "",
                                  response=True)

        resp = Response(hinfo["data"], headers=hinfo["headers"])
        return resp(self.environ, self.start_response)

# ----------------------------------------------------------------------------
# === Authn query service ===
# ----------------------------------------------------------------------------


# Only SOAP binding
class AQS(Service):
    def do(self, request, binding, relay_state=""):
        self.logger.info("--- Authn Query Service ---")
        _req = self.IDP.parse_authn_query(request, binding)
        _query = _req.message

        msg = self.IDP.create_authn_query_response(_query.subject,
                                              _query.requested_authn_context,
                                              _query.session_index)

        self.logger.debug("response: %s" % msg)
        hinfo = self.IDP.apply_binding(BINDING_SOAP, "%s" % msg, "", "",
                                  response=True)

        resp = Response(hinfo["data"], headers=hinfo["headers"])
        return resp(self.environ, self.start_response)


# ----------------------------------------------------------------------------
# === Attribute query service ===
# ----------------------------------------------------------------------------


# Only SOAP binding
class ATTR(Service):
    def do(self, request, binding, relay_state=""):
        self.logger.info("--- Attribute Query Service ---")

        _req = self.IDP.parse_attribute_query(request, binding)
        _query = _req.message

        name_id = _query.subject.name_id
        uid = name_id.text
        self.logger.debug("Local uid: %s" % uid)
        identity = EXTRA[uid]

        # Comes in over SOAP so only need to construct the response
        args = self.IDP.response_args(_query, [BINDING_SOAP])
        msg = self.IDP.create_attribute_response(identity,
                                            name_id=name_id, **args)

        self.logger.debug("response: %s" % msg)
        hinfo = self.IDP.apply_binding(BINDING_SOAP, "%s" % msg, "", "",
                                  response=True)

        resp = Response(hinfo["data"], headers=hinfo["headers"])
        return resp(self.environ, self.start_response)

# ----------------------------------------------------------------------------
# Name ID Mapping service
# When an entity that shares an identifier for a principal with an identity
# provider wishes to obtain a name identifier for the same principal in a
# particular format or federation namespace, it can send a request to
# the identity provider using this protocol.
# ----------------------------------------------------------------------------


class NIM(Service):
    def do(self, query, binding, relay_state=""):
        req = self.IDP.parse_name_id_mapping_request(query, binding)
        request = req.message
        # Do the necessary stuff
        try:
            name_id = self.IDP.ident.handle_name_id_mapping_request(
                request.name_id, request.name_id_policy)
        except Unknown:
            resp = BadRequest("Unknown entity")
            return resp(self.environ, self.start_response)
        except PolicyError:
            resp = BadRequest("Unknown entity")
            return resp(self.environ, self.start_response)

        info = self.IDP.response_args(request)
        _resp = self.IDP.create_name_id_mapping_response(name_id, **info)

        # Only SOAP
        hinfo = self.IDP.apply_binding(BINDING_SOAP, "%s" % _resp, "", "",
                                  response=True)

        resp = Response(hinfo["data"], headers=hinfo["headers"])
        return resp(self.environ, self.start_response)


# ----------------------------------------------------------------------------
# Cookie handling
# ----------------------------------------------------------------------------
def info_from_cookie(kaka, IDP, logger):
    logger.debug("KAKA: %s" % kaka)
    if kaka:
        cookie_obj = SimpleCookie(kaka)
        morsel = cookie_obj.get("idpauthn", None)
        if morsel:
            try:
                key, ref = base64.b64decode(morsel.value).split(":")
                return IDP.cache.uid2user[key], ref
            except KeyError:
                return None, None
        else:
            logger.debug("No idpauthn cookie")
    return None, None


def delete_cookie(environ, name, logger):
    kaka = environ.get("HTTP_COOKIE", '')
    logger.debug("delete KAKA: %s" % kaka)
    if kaka:
        cookie_obj = SimpleCookie(kaka)
        morsel = cookie_obj.get(name, None)
        cookie = SimpleCookie()
        cookie[name] = ""
        cookie[name]['path'] = "/"
        logger.debug("Expire: %s" % morsel)
        cookie[name]["expires"] = _expiration("dawn")
        return tuple(cookie.output().split(": ", 1))
    return None


def set_cookie(name, _, logger, *args):
    cookie = SimpleCookie()
    cookie[name] = base64.b64encode(":".join(args))
    cookie[name]['path'] = "/"
    cookie[name]["expires"] = _expiration(5)  # 5 minutes from now
    logger.debug("Cookie expires: %s" % cookie[name]["expires"])
    return tuple(cookie.output().split(": ", 1))

# ----------------------------------------------------------------------------

# map urls to functions
AUTHN_URLS = [
    # sso
    (r'sso/post$', (SSO, "post")),
    (r'sso/post/(.*)$', (SSO, "post")),
    (r'sso/redirect$', (SSO, "redirect")),
    (r'sso/redirect/(.*)$', (SSO, "redirect")),
    (r'sso/art$', (SSO, "artifact")),
    (r'sso/art/(.*)$', (SSO, "artifact")),
    # slo
    (r'slo/redirect$', (SLO, "redirect")),
    (r'slo/redirect/(.*)$', (SLO, "redirect")),
    (r'slo/post$', (SLO, "post")),
    (r'slo/post/(.*)$', (SLO, "post")),
    (r'slo/soap$', (SLO, "soap")),
    (r'slo/soap/(.*)$', (SLO, "soap")),
    #
    (r'airs$', (AIDR, "uri")),
    (r'ars$', (ARS, "soap")),
    # mni
    (r'mni/post$', (NMI, "post")),
    (r'mni/post/(.*)$', (NMI, "post")),
    (r'mni/redirect$', (NMI, "redirect")),
    (r'mni/redirect/(.*)$', (NMI, "redirect")),
    (r'mni/art$', (NMI, "artifact")),
    (r'mni/art/(.*)$', (NMI, "artifact")),
    (r'mni/soap$', (NMI, "soap")),
    (r'mni/soap/(.*)$', (NMI, "soap")),
    # nim
    (r'nim$', (NIM, "soap")),
    (r'nim/(.*)$', (NIM, "soap")),
    #
    (r'aqs$', (AQS, "soap")),
    (r'attr$', (ATTR, "soap"))
]

NON_AUTHN_URLS = [
    (r'login?(.*)$', do_authentication),
    (r'verify?(.*)$', do_verify),
    (r'sso/ecp$', (SSO, "ecp")),
]

# ----------------------------------------------------------------------------


from mako.lookup import TemplateLookup

ROOT = './'
LOOKUP = TemplateLookup(directories=[ROOT + 'templates', ROOT + 'htdocs'],
                        module_directory=ROOT + 'modules',
                        input_encoding='utf-8', output_encoding='utf-8')

# ----------------------------------------------------------------------------

def static_filename(config, path):
    if not isinstance(path, basestring):
        return False
    if not config.static_dir:
        return False
    try:
        filename = os.path.join(config.static_dir, path)
        os.stat(filename)
        return filename
    except OSError:
        return None

def static_file(environ, start_response, filename):
    try:
        text = open(filename).read()
        if filename.endswith(".ico"):
            resp = Response(text, headers=[('Content-Type', "image/x-icon")])
        elif filename.endswith(".html"):
            resp = Response(text, headers=[('Content-Type', 'text/html')])
        elif filename.endswith(".css"):
            resp = Response(text, headers=[('Content-Type', 'text/css')])
        elif filename.endswith(".js"):
            # Content-Type: application/javascript; charset=utf-8
            resp = Response(text, headers=[('Content-Type', 'application/javascript')])
        elif filename.endswith(".txt"):
            resp = Response(text, headers=[('Content-Type', 'text/plain')])
        else:
            resp = Response(text, headers=[('Content-Type', 'text/xml')])
    except IOError:
        resp = NotFound()
    return resp(environ, start_response)


class IdPApplication(object):

    def __init__(self, logger, config):
        self.logger = logger
        self.config = config
        self.response_status = None
        self.start_response = None

        import socket
        authn_authority = "http://%s" % socket.gethostname()

        self.AUTHN_BROKER = AuthnBroker()
        self.AUTHN_BROKER.add(authn_context_class_ref(PASSWORD), username_password_authn, 10, authn_authority)
        self.AUTHN_BROKER.add(authn_context_class_ref(UNSPECIFIED), "", 0, authn_authority)

        self.IDP = server.Server(config.pysaml2_config, cache=Cache())
        self.IDP.ticket = {}

    def application(self, environ, start_response):
        """
        The main WSGI application. Dispatch the current request to
        the functions from above and store the regular expression
        captures in the WSGI environment as  `myapp.url_args` so that
        the functions from above can access the url placeholders.

        If nothing matches call the `not_found` function.

        :param environ: The HTTP application environment
        :param start_response: The application to run when the handling of the
        request is done
        :return: The response as a list of lines
        """

        path = environ.get('PATH_INFO', '').lstrip('/')
        kaka = environ.get("HTTP_COOKIE", None)
        self.logger.info("<application> PATH: %s" % path)

        if kaka:
            self.logger.info("= KAKA =")
            user, authn_ref = info_from_cookie(kaka, self.IDP, self.logger)
            environ["idp.authn_ref"] = authn_ref
        else:
            try:
                query = parse_qs(environ["QUERY_STRING"])
                self.logger.debug("QUERY: %s" % query)
                user = self.IDP.cache.uid2user[query["id"][0]]
            except KeyError:
                user = None

        static_fn = static_filename(self.config, path)
        self.logger.debug("STATIC FILENAME {!r}".format(static_fn))
        if static_fn:
            return static_file(environ, start_response, static_fn)

        url_patterns = AUTHN_URLS
        if not user:
            self.logger.info("-- No USER --")
            # insert NON_AUTHN_URLS first in case there is no user
            url_patterns = NON_AUTHN_URLS + url_patterns

        for regex, callback in url_patterns:
            match = re.search(regex, path)
            if match is not None:
                try:
                    environ['myapp.url_args'] = match.groups()[0]
                except IndexError:
                    environ['myapp.url_args'] = path

                self.logger.debug("Callback: %s" % (callback,))
                if isinstance(callback, tuple):
                    cls = callback[0](environ, start_response, self, user)
                    func = getattr(cls, callback[1])
                    return func()
                return callback(environ, start_response, self, user)

        return not_found(environ, start_response)

# ----------------------------------------------------------------------------



def main(myname = 'eduid.saml2.idp'):
    """
    Initialize everything and start the IdP application.
    """
    args = parse_args()

    # initialize various components
    logger = logging.getLogger(myname)
    config = eduid_idp.config.IdPConfig(args.config_file, args.debug)
    if config.debug:
        logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s %(name)s: %(levelname)s %(message)s')
        stream_h = logging.StreamHandler(sys.stderr)
        stream_h.setFormatter(formatter)
        logger.addHandler(stream_h)

    cherry_conf = {'server.thread_pool': config.num_threads,
                   'server.socket_port': config.listen_port,
                   # enables X-Forwarded-For, since BCP is to run this server
                   # behind a webserver that handles SSL
                   'tools.proxy.on': True,
                   }
    if config.logdir:
        cherry_conf['log.access_file'] = os.path.join(config.logdir, 'access.log')
        cherry_conf['log.error_file'] = os.path.join(config.logdir, 'error.log')
    else:
        sys.stderr.write("NOTE: Config option 'logdir' not set.\n")
    cherrypy.config.update(cherry_conf)

#    cherrypy.quickstart(IdPApplication(config))

    app = IdPApplication(logger, config)
    bind_addr = (config.listen_addr, config.listen_port)
    SRV = cherrypy.wsgiserver.CherryPyWSGIServer(bind_addr, app.application)

    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
        raise


if __name__ == '__main__':
    from idp_user import USERS
    from idp_user import EXTRA

    try:
        progname = os.path.basename(sys.argv[0])
        if main(progname):
            sys.exit(0)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)
