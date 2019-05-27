# -*- coding: utf-8 -*-
#
# Copyright (c) 2019 SUNET
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
from typing import Optional, List, Tuple

DEBUG: bool = False
DEVELOPMENT: bool = DEBUG

# The Redis host to use for session storage.
REDIS_HOST: Optional[str] = None

# The port of the Redis server (integer).
REDIS_PORT: int = 6379

# The Redis database number (integer).
REDIS_DB: int = 0

# Redis sentinel hosts, comma separated
REDIS_SENTINEL_HOSTS: Optional[List[str]] = None

# The Redis sentinel 'service name'.
REDIS_SENTINEL_SERVICE_NAME: Optional[str] = None

# The Redis session encrypted application key.
SESSION_APP_KEY: Optional[str] = None

# Secret key
SECRET_KEY: Optional[str] = None

# Logging
LOG_LEVEL: str = 'DEBUG'

# IdP specific
SYSLOG_DEBUG: bool = False

NUM_THREADS = 8

LOGDIR = None

LOGFILE = None

SYSLOG_SOCKET = None            # syslog socket to log to (/dev/log maybe)

# IP address to listen on.
LISTEN_ADDR: str = '0.0.0.0'

# The port the IdP authentication should listen on (integer).
LISTEN_PORT: int = 8088

# pysaml2 configuration file. Separate config file with SAML related parameters.
PYSAML2_CONFIG: str = 'eduid_webapp.idp.idp_conf'

# SAML F-TICKS user anonymization key. If this is set, the IdP will log FTICKS data
# on every login.
FTICKS_SECRET_KEY: Optional[str] = None

# Get SAML F-TICKS format string.
FTICKS_FORMAT_STRING: str = 'F-TICKS/SWAMID/2.0#TS={ts}#RP={rp}#AP={ap}#PN={pn}#AM={am}#'

STATIC_DIR = None   # directory for local static files

STATIC_LINK = '#'   # URL to static resources that can be used in templates

SSL_ADAPTER = 'builtin'  # one of cherrypy.wsgiserver.ssl_adapters

# SSL certificate filename (None == SSL disabled)
SERVER_CERT: Optional[str] = None  # SSL cert filename

# SSL private key filename (None == SSL disabled)
SERVER_KEY: Optional[str] = None   # SSL key filename

# SSL certificate chain filename
CERT_CHAIN: Optional[str] = None   # SSL certificate chain filename, or None

#  UserDB database name.
USERDB_MONGO_DATABASE: str = 'eduid_am'  # eduid_am for old userdb, eduid_userdb for new

# MongoDB connection URI (string). See MongoDB documentation for details.
MONGO_URI: Optional[str] = None    # Base mongodb:// URI

# MongoDB connection URI (string) for PySAML2 SSO sessions.
SSO_SESSION_MONGO_URI: Optional[str] = None   # mongodb:// URI for SSO session cache

# Lifetime of SSO session (in minutes).
# If a user has an active SSO session, they will get SAML assertions made
# without having to authenticate again (unless SP requires it through
# ForceAuthn).
# The total time a user can access a particular SP would therefor be
# this value, plus the pysaml2 lifetime of the assertion.
SSO_SESSION_LIFETIME: int = 15  # Lifetime of SSO session in minutes

# Raven DSN (string) for logging exceptions to Sentry.
RAVEN_DSN: Optional[str] = None

CONTENT_PACKAGES: List[Tuple[str]] = []  # List of Python packages ("name:path") with content resources

# Verify request signatures, if they exist.
# This defaults to False since it is a trivial DoS to consume all the IdP:s
# CPU resources if this is set to True.
VERIFY_REQUEST_SIGNATURES: bool = False

# Get list of usernames valid for use with the /status URL.
# If this list is ['*'], all usernames are allowed for /status.
STATUS_TEST_USERNAMES: Optional[List[str]] = None

# URL (string) for use in simple templating of login.html.
SIGNUP_LINK: str = '#'          # for login.html

# URL (string) for use in simple templating of forbidden.html.
DASHBOARD_LINK: str = '#'       # for forbidden.html

# URL (string) for use in simple templating of login.html.
PASSWORD_RESET_LINK: str = '#'  # for login.html

# More links
TECHNICIANS_LINK: str = '#'
STUDENT_LINK: str = '#'
STAFF_LINK: str = '#'
FAQ_LINK: str = '#'

# Default language code to use when looking for web pages ('en').
DEFAULT_LANGUAGE: str = 'en'

# Base URL of the IdP. The default base URL is constructed from the
# Request URI, but for example if there is a load balancer/SSL
# terminator in front of the IdP it might be required to specify
# the URL of the service.
BASE_URL: Optional[str] = None

# The scope to append to any unscoped eduPersonPrincipalName
# attributes found on users in the userdb.
DEFAULT_EPPN_SCOPE: Optional[str] = None

# Disallow login for a user after N failures in a given month.
# This is said to be an imminent Kantara requirement.
MAX_AUTHN_FAILURES_PER_MONTH: int = 50  # Kantara 30-day bad authn limit is 100

# Lifetime of state kept in IdP login phase.
# This is the time, in minutes, a user has to complete the login phase.
# After this time, login cannot complete because the SAMLRequest, RelayState
# and possibly other needed information will be forgotten.
LOGIN_STATE_TTL: int = 5   # time to complete an IdP login, in minutes

# Add a default eduPersonScopedAffiliation if none is returned from the
# attribute manager.
DEFAULT_SCOPED_AFFILIATION: Optional[str] = None

# URL to use with VCCS client. BCP is to have an nginx or similar on
# localhost that will proxy requests to a currently available backend
# using TLS.
VCCS_URL: str = 'http://localhost:8550/'  # VCCS backend URL

INSECURE_COOKIES: bool = False

# URI of the actions app.
ACTIONS_APP_URI: Optional[str] = 'http://actions.example.com/'

# The plugins for pre-authentication actions that need to be loaded
ACTION_PLUGINS: List[str] = []

# The current version of the terms of use agreement.
TOU_VERSION: str = 'version1'

# The interval which a user needs to reaccept an already accepted ToU (in seconds)
TOU_REACCEPT_INTERVAL: int = 94608000

# Name of cookie used to persist session information in the users browser.
SHARED_SESSION_COOKIE_NAME: str = 'sessid'

# Key to decrypt shared sessions.
SHARED_SESSION_SECRET_KEY: Optional[str] = None

# TTL for shared sessions.
SHARED_SESSION_TTL: int = 300
