#!/usr/bin/env python
#
# XXX check ../ handling in static file handling


"""
eduID IdP application


General user<->IdP interaction flow :


  1) User visits protected page at SP, which redirects user to
     URL /sso/redirect?SAMLRequest=base64-AuthnRequest

  2) URL /sso/redirect is handled by SSO.redirect()

     SSO.redirect() creates SHA-1 of SAML AuthnRequest and uses this as key to store
     some info in a cache called IDP.ticket. The information stored includes all the
     URI parameters.

     The key is passed to the login form HTML template as {{key}}.

     Another hash, a reference to the authn context is generated (by pysaml2
     authn_context code) and passed to the template as {{authn_reference}}.

     The current URL is included in the HTML form as {{redirect_uri}}.

  3) User fills out login form an POSTs it to URL /verify

  4) URL /verify is handled by do_verify()

     do_verify() tries to authenticate user based on filled out HTML form contents.

     If successful, a random user identifier is created and a mapping between the
     random uid and the real authenticated users username is stored in the IDP.cache.

     The random user identifier and the authn_reference from step 2 is stored in a
     browser cookie called `idpauthn'.

     The user is HTTP redirected back to the URL of step 2 through the `redirect_uri'
     HTML parameter (included in the HTML form by step 2). The random user identifier
     is passed as URL parameter `id', and the `authn_reference' from step 2 is passed
     as URL parameter `key'.

  5) URL /sso/redirect (re-visited) is handled by SSO.redirect()

     Since the query string includes a `key' that can be used to look up info from
     IDP.ticket this time, processing is continued in SSO.do() (via SSO.operation()).
     The info in IDP.ticket is pruned first.

     SSO.do() gets the original URI parameters from step 2 that were stored in
     IDP.ticket, and rounds up identity information for the user.

     SSO.do() effectively uses IdPApplication.application() to determine which
     user is logged in. This will be either from the idpauthn cookie being set,
     and containing a random user identifier that can be looked up in IDP.cache
     to get a real username, or from IDP.cache using the `id' URI parameter.

     An AuthnResponse is created using pysaml2 create_authn_response(), and this
     is where the `authn_reference' from step 2 seems to come into play. The authn
     reference is used to locate the correct authn instance (the same one used
     in step 2) with the AUTHN_BROKER.

"""

import os
import re
import sys
import time
import base64
import pprint
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
from saml2.s_utils import rndstr, exception_trace
from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding
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

class TicketCache():

    def __init__(self, logger):
        self.logger = logger
        self._data = {}

    def key(self, SAMLRequest):
        return sha1(SAMLRequest).hexdigest()

    def add(self, key, info):
        assert("SAMLRequest" in info)
        self._data[key] = info

    def get(self, key):
        return self._data.get(key)

    def items(self):
        return self._data

    def delete(self, key):
        if key in self._data:
            del self._data[key]
        else:
            self.logger.debug("FREDRIK: FAILED DELETING {!r} FROM\n{!s}".format(
                    key, pprint.pformat(self._data)))

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
        idp_app.logger.debug("ENVIRON:\n{!s}".format(pprint.pformat(environ)))
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

    def not_authn(self, key, requested_authn_context):
        """
        Authenticate user. Either, the user hasn't logged in yet,
        or the service provider forces re-authentication.
        """
        redirect_uri = geturl(self.environ, query=False)

        self.logger.debug("Do authentication, requested auth context : {!r}".format(requested_authn_context))

        auth_info = self.AUTHN_BROKER.pick(requested_authn_context)

        if len(auth_info):
            method, reference = auth_info[0]
            self.logger.debug("Authn chosen: %s (ref=%s)" % (method, reference))
            # `method' is, for example, the function username_password_authn
            return method(self.environ, self.start_response, reference, key,
                          redirect_uri, self.logger, self.config)
        else:
            resp = Unauthorized("No usable authentication method")
            return resp(environ, start_response)


# -----------------------------------------------------------------------------
# === Single log in ====
# -----------------------------------------------------------------------------


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
            self.logger.info("SAML query parsed OK")
        else:
            self.logger.debug("verify_request acting on previously parsed self.req_info {!s}".format(
                    self.req_info))

        _authn_req = self.req_info.message
        self.logger.debug("AuthnRequest {!r} :\n{!s}".format(_authn_req, _authn_req))

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
        self.logger.debug("\n\n---\n\n")
        self.logger.debug("--- In SSO.do() ---")
        try:
            resp_args, _resp = self.verify_request(query, binding_in)
        except UnknownPrincipal, excp:
            self.logger.error("Could not verify request: UnknownPrincipal: %s" % (excp,))
            resp = ServiceError("UnknownPrincipal: %s" % (excp,))
            return resp(self.environ, self.start_response)
        except UnsupportedBinding, excp:
            self.logger.error("Could not verify request: UnsupportedBinding: %s" % (excp,))
            resp = ServiceError("UnsupportedBinding: %s" % (excp,))
            return resp(self.environ, self.start_response)

        if not _resp:
            identity = USERS[self.user]
            self.logger.info("Identity:\n{!s}".format(pprint.pformat(identity)))

            try:
                _authn = self.AUTHN_BROKER[self.environ["idp.authn_ref"]]
                self.logger.debug("Re-created authn {!r} using idp.authn_ref {!r}".format(
                        _authn, self.environ["idp.authn_ref"]))
                self.logger.debug("Creating an AuthnResponse, user {!r}".format(self.user))
                _resp = self.IDP.create_authn_response(
                    identity, userid=self.user,
                    authn=_authn,
                    **resp_args)
            except Exception, excp:
                self.logger.error("Failed creating AuthnResponse:\n {!s}".format(exception_trace(excp)))
                self.logger.debug("AuthN-by-ref {!r} not found in list :\n{!s}".format(
                        self.environ["idp.authn_ref"], pprint.pformat(self.AUTHN_BROKER.db["info"])))
                resp = ServiceError("Exception: %s" % (excp,))
                return resp(self.environ, self.start_response)

        # XXX clean IDP.ticket here!

        self.logger.info("AuthNResponse {!r} :\n{!s}".format(_resp, _resp))
        # Create the Javascript self-posting form that will take the user back to the SP
        # with a SAMLResponse
        http_args = self.IDP.apply_binding(self.binding_out,
                                           "%s" % _resp, self.destination,
                                           relay_state, response=True)
        self.logger.debug("HTTPargs :\n{!s}".format(pprint.pformat(http_args)))
        return self.response(self.binding_out, http_args)


    def redirect(self):
        """ This is the HTTP-redirect endpoint """
        self.logger.info("--- In SSO Redirect ---")
        _info = self.unpack_redirect()
        self.logger.debug("FREDRIK: Unpacked redirect :\n{!s}".format(pprint.pformat(_info)))

        _res, _ticket = self._get_ticket(_info)
        if not _res:
            # result was an WSGI error response function
            return _ticket(self.environ, self.start_response)
        self.req_info = _ticket['req_info']

        _fc = _ticket.get("FailCount", 0)
        if _fc:
            self.environ['idp.FailCount'] = _fc

        # re-insert in IDP.ticket cache
        _ticket["FailCount"] = _fc + 1
        key = self._store_ticket(_ticket)

        if not self.user:
            self.logger.info("Not authenticated")
            return self.not_authn(key, self.req_info.message.requested_authn_context)
        else:
            self.logger.debug("Continuing with user {!r}".format(self.user))

        if self.req_info.message.force_authn:
            self.logger.info("Forcing authentication for user {!r}".format(self.user))
            return self.not_authn(key, self.req_info.message.requested_authn_context)

        self.logger.debug("Continuing with Authn request {!r}".format(self.req_info))
        return self.operation(_ticket, BINDING_HTTP_REDIRECT)


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
                key = self._store_ticket(_info)
                return self.not_authn(key, _req.requested_authn_context)
            else:
                return self.operation(_info, BINDING_HTTP_POST)
        else:
            _info["req_info"] = self.req_info
            key = self._store_ticket(_info)
            return self.not_authn(key, _req.requested_authn_context)


    def _store_ticket(self, _ticket):
        """
        Add an entry to the IDP.ticket cache.

        Ticket must contain SAMLRequest and is typically

        {'RelayState': '/path',
         'SAMLRequest': 'nVLB...==',
         'req_info': <saml2.request.AuthnRequest object>,
         ...
        }

        :returns: Key as string
        """
        key = self.IDP.ticket.key(_ticket["SAMLRequest"])
        self.logger.debug("_store_ticket in IDP.ticket (key {!r}):\n{!s}".format(key, pprint.pformat(_ticket)))
        # store the AuthnRequest
        self.IDP.ticket.add(key, _ticket)
        return key


    def _get_ticket(self, _info):
        """
        _info is redirect HTTP query parameters.

        Will include a 'key' parameter, or a 'SAMLRequest'.

        Ticket is typically

        {'RelayState': '/path',
         'SAMLRequest': 'nVLB...==',
         'req_info': <saml2.request.AuthnRequest object>,
         ...
        }

        :returns: ResultBool, Ticket as dict
        """
        # Try ticket-cache lookup based on key, or key derived from SAMLRequest
        _key = None
        if "key" in _info:
            _key = _info["key"]
        elif "SAMLRequest" in _info:
            _key = self.IDP.ticket.key(_info["SAMLRequest"])
        else:
            return False, BadRequest("Missing SAMLRequest, please re-initiate login")
        # lookup
        _data = self.IDP.ticket.get(_key)

        if _data is None:
            self.logger.debug("FREDRIK: Key {!r} not found in IDP.ticket :\n{!s}".format(
                     _key, pprint.pformat(self.IDP.ticket.items())))
            if "key" in _info:
                return False, BadRequest("Missing IdP ticket, please re-initiate login")
             # cache miss, parse SAMLRequest
            _data = _info
            _data["req_info"] = self._parse_SAMLRequest(_info)
        else:
            self.logger.debug("FREDRIK: Retreived IDP.ticket(key={!r}) :\n{!s}".format(
                    _key, pprint.pformat(_data)))

        return True, _data


    def _parse_SAMLRequest(self, _info):
        """
        Parse a SAMLRequest query parameter (base64 encoded) into an AuthnRequest
        instance.

        If the SAMLRequest is signed, the signature is validated and a BadRequest()
        returned on failure.

        :returns: AuthnRequest or BadRequest() instance
        """
        _req_info = self.IDP.parse_authn_request(_info["SAMLRequest"], BINDING_HTTP_REDIRECT)

        self.logger.debug("Decoded SAMLRequest into AuthnRequest {!r} :\n{!s}".format(
                _req_info.message, _req_info.message))

        if "SigAlg" in _info and "Signature" in _info:  # Signed request
            issuer = _req_info.message.issuer.text
            _certs = self.IDP.metadata.certs(issuer, "any", "signing")
            verified_ok = False
            for cert in _certs:
                if verify_redirect_signature(_info, cert):
                    verified_ok = True
                    break
            if not verified_ok:
                resp = BadRequest("Message signature verification failure")
                return resp(self.environ, self.start_response)
        else:
            self.logger.debug("No signature in SAMLRequest")
        return _req_info


# -----------------------------------------------------------------------------
# === Authentication ====
# -----------------------------------------------------------------------------


def username_password_authn(environ, start_response, reference, key,
                            redirect_uri, logger, config):
    """
    Display the login form
    """
    argv = {
        "action": "/verify",
        "username": "",
        "password": "",
        "key": key,
        "authn_reference": reference,
        "redirect_uri": redirect_uri,
        "alert_msg": "",
    }

    _fc = environ.get("idp.FailCount", 0)
    try:
        _fc = int(_fc)
    except ValueError:
        logger.debug("Bad (non-integer) FailCount : {!r}".format(_fc))
        pass
    else:
        if _fc > 0:
            argv["alert_msg"] = "Incorrect username or password (%i attempts)" % (_fc)

    logger.debug("Login page HTML substitution arguments :\n{!s}".format(pprint.pformat(argv)))

    static_fn = static_filename(config, 'login.html')

    if static_fn:
        res = static_file(environ, start_response, static_fn)
        if len(res) == 1:
            res = res[0]
        # apply simplistic HTML formatting to template in 'res'
        return res.format(**argv)

    return not_found(environ, start_response)


def verify_username_and_password(dic):
    PASSWD = {"roland": "dianakra",
              "babs": "howes",
              "upper": "crust"}

    # verify username and password
    username_param = dic["username"][0]
    if PASSWD[username_param] == dic["password"][0]:
        return True, username_param
    else:
        return False, ""


def do_verify(environ, start_response, idp_app, _user):
    query = parse_qs(get_post(environ))

    # XXX remove password from query before logging
    idp_app.logger.debug("do_verify parsed query :\n{!s}".format(pprint.pformat(query)))

    idp_app.logger.debug("ENVIRON:\n{!s}".format(pprint.pformat(environ)))

    try:
        # XXX need to verify that UsernamePassword is an appropriate authn context here I think
        _ok, user = verify_username_and_password(query)
    except KeyError:
        _ok = False
        user = None

    if not _ok:
        idp_app.logger.info("Unknown user or wrong password")
        if "HTTP_REFERER" in environ:
            _qs = environ["HTTP_REFERER"]
            _fc = environ.get("idp.FailCount", 0)
            try:
                _fc = int(_fc)
            except ValueError:
                logger.debug("Bad (non-integer) FailCount : {!r}".format(_fc))

            lox = "%s" % (environ["HTTP_REFERER"])
            resp = Redirect(lox, content="text/html")
        else:
            resp = Unauthorized("Unknown user or wrong password")
    else:
        idp_app.logger.debug("FREDRIK: User {!r} authenticated OK".format(user))
        uid = rndstr(24)
        idp_app.IDP.cache.uid2user[uid] = user
        idp_app.IDP.cache.user2uid[user] = uid
        idp_app.logger.debug("Register %s under '%s'" % (user, uid))

        idp_app.logger.debug("FREDRIK: Storing uid={!r} and authn_reference={!r} in idpauthn cookie".format(
                uid, query["authn_reference"][0]))
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
            self.logger.debug("Purging from cache, uid : {!s}".format(self.IDP.cache.uid2user[self.IDP.cache.user2uid[lid]]))
            self.logger.debug("Purging from cache, lid : {!s}".format(self.IDP.cache.user2uid[lid]))
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
# Cookie handling
# ----------------------------------------------------------------------------
def info_from_cookie(kaka, IDP, logger):
    """
    Decode information stored in a browser cookie.

    XXX this cookie needs to be MAC:d - or better.

    :returns: Username, AuthnRef
    """
    logger.debug("Parsing cookie(s): %s" % kaka)
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
    logger.debug("set KAKA: %s" % cookie)
    return tuple(cookie.output().split(": ", 1))

# ----------------------------------------------------------------------------

# map urls to functions
AUTHN_URLS = [
    # sso
    (r'sso/post$', (SSO, "post")),
    (r'sso/post/(.*)$', (SSO, "post")),
    (r'sso/redirect$', (SSO, "redirect")),
    (r'sso/redirect/(.*)$', (SSO, "redirect")),
    (r'sso/art$', (SSO, "artifact")),		# seldomly used, but part of standard
    (r'sso/art/(.*)$', (SSO, "artifact")),	# seldomly used, but part of standard
    # slo
    (r'slo/redirect$', (SLO, "redirect")),
    (r'slo/redirect/(.*)$', (SLO, "redirect")),
    (r'slo/post$', (SLO, "post")),
    (r'slo/post/(.*)$', (SLO, "post")),
    (r'slo/soap$', (SLO, "soap")),		# SOAP is commonly used for SLO
    (r'slo/soap/(.*)$', (SLO, "soap")),		# SOAP is commonly used for SLO
]

NON_AUTHN_URLS = [
    (r'verify?(.*)$', do_verify),
    #(r'sso/ecp$', (SSO, "ecp")),   # ECP is for eduID > 1
]

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
        elif filename.endswith(".png"):
            resp = Response(text, headers=[('Content-Type', 'image/png')])
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
        #self.AUTHN_BROKER.add(authn_context_class_ref(PASSWORD), two_factor_authn, 20, authn_authority)
        self.AUTHN_BROKER.add(authn_context_class_ref(PASSWORD), username_password_authn, 10, authn_authority)
        self.AUTHN_BROKER.add(authn_context_class_ref(UNSPECIFIED), "", 0, authn_authority)

        self.IDP = server.Server(config.pysaml2_config, cache=Cache())
        self.IDP.ticket = TicketCache(logger)

    def my_start_response(self, status, headers):
        self.logger.debug("FREDRIK: START RESPONSE {!r}, HEADERs {!r}".format(status, headers))
        self.response_status = status
        return self.start_response(status, headers)

    def application(self, environ, start_response):
        self.start_response = start_response
        res = self.application2(environ, self.my_start_response)
        if isinstance(res, list):
            res = ''.join(res)
        if len(res) < 200:
            self.logger.debug("FREDRIK: APP RESPONSE {!r} :\n{!r}".format(self.response_status, res))
        else:
            self.logger.debug("FREDRIK: APP RESPONSE {!r} : {!r} bytes".format(self.response_status, len(res)))
        return res

    def application2(self, environ, start_response):
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
        self.logger.debug("\n\n-----\n\n")
        self.logger.info("<application> PATH: %s" % path)

        static_fn = static_filename(self.config, path)
        if static_fn:
            self.logger.debug("SERVING STATIC FILE {!r}".format(static_fn))
            return static_file(environ, start_response, static_fn)
        if path.startswith("static/") or path == "favicon.ico":
            return not_found(environ, start_response)

        if kaka:
            # XXX retreiving the authn_ref from an unsecured cookie lets malicious people
            # 'upgrade' their logins to higher authentication contexts!
            user, authn_ref = info_from_cookie(kaka, self.IDP, self.logger)
            self.logger.debug("Decoded info from idpauthn cookie : user={!r}, authn_ref={!r}".format(
                    user, authn_ref))
            environ["idp.authn_ref"] = authn_ref
        else:
            try:
                query = parse_qs(environ["QUERY_STRING"])
                self.logger.debug("FREDRIK: QUERY:\n{!s}".format(pprint.pformat(query)))
                user = self.IDP.cache.uid2user[query["id"][0]]
                self.logger.debug("FREDRIK: Looked up user={!r} from cache(id={!r})".format(user, query["id"][0]))
            except KeyError:
                self.logger.debug("FREDRIK: No user")
                user = None

        url_patterns = AUTHN_URLS
        if not user:
            self.logger.info("-- No USER --")
            # insert NON_AUTHN_URLS first in case there is no user
            url_patterns = NON_AUTHN_URLS + url_patterns
        else:
            self.logger.info("FREDRIK: USER {!r}".format(user))

        for regex, callback in url_patterns:
            match = re.search(regex, path)
            self.logger.debug("match path {!r} to re {!r} -> {!r}".format(path, regex, match))
            if match is not None:
                # The 'myapp' thingy is unused legacy according to Roland
                #try:
                #    environ['myapp.url_args'] = match.groups()[0]
                #except IndexError:
                #    environ['myapp.url_args'] = path
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
        formatter = logging.Formatter('%(asctime)s %(name)s %(threadName)s: %(levelname)s %(message)s')
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

    try:
        progname = os.path.basename(sys.argv[0])
        if main(progname):
            sys.exit(0)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)
