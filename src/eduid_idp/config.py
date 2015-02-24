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
Configuration (file) handling for eduID IdP.
"""

import os
import ConfigParser

_CONFIG_DEFAULTS = {'debug': False,  # overwritten in IdPConfig.__init__()
                    'syslog_debug': '0',              # '1' for True, '0' for False
                    'num_threads': '8',
                    'logdir': None,
                    'logfile': None,
                    'syslog_socket': None,            # syslog socket to log to (/dev/log maybe)
                    'listen_addr': '0.0.0.0',
                    'listen_port': '8088',
                    'pysaml2_config': 'idp_conf.py',  # path prepended in IdPConfig.__init__()
                    'fticks_secret_key': None,
                    'fticks_format_string': 'F-TICKS/SWAMID/2.0#TS={ts}#RP={rp}#AP={ap}#PN={pn}#AM={am}#',
                    'static_dir': None,
                    'ssl_adapter': 'builtin',  # one of cherrypy.wsgiserver.ssl_adapters
                    'server_cert': None,  # SSL cert filename
                    'server_key': None,   # SSL key filename
                    'cert_chain': None,   # SSL certificate chain filename, or None
                    'userdb_mongo_uri': None,
                    'userdb_mongo_database': None,
                    'sso_session_lifetime': '15',  # Lifetime of SSO session in minutes
                    'sso_session_mongo_uri': None,
                    'raven_dsn': None,
                    'content_packages': [],  # List of Python packages ("name:path") with content resources
                    'verify_request_signatures': '0',  # '1' for True, '0' for False
                    'status_test_usernames': [],
                    'signup_link': '#',  # for login.html
                    'dashboard_link': '#',  # for forbidden.html
                    'password_reset_link': '#',  # for login.html
                    'default_language': 'en',
                    'base_url': None,
                    'default_eppn_scope': None,
                    'authn_info_mongo_uri': None,
                    'max_authn_failures_per_month': '50',  # Kantara 30-day bad authn limit is 100
                    'login_state_ttl': '5',   # time to complete an IdP login, in minutes
                    'default_scoped_affiliation': None,
                    'vccs_url': 'http://localhost:8550/',    # VCCS backend URL
                    'insecure_cookies': '0',                     # Set to 1 to not set HTTP Cookie 'secure' flag
                    }

_CONFIG_SECTION = 'eduid_idp'


class IdPConfig(object):

    """
    Class holding IdP application configuration.

    Loads configuration from an INI-file at instantiation.

    :param filename: string, INI-file name
    :param debug: boolean, default debug value
    :raise ValueError: if INI-file can't be parsed
    """

    def __init__(self, filename, debug):
        self._parsed_content_packages = None
        self._parsed_status_test_usernames = None
        self.section = _CONFIG_SECTION
        _CONFIG_DEFAULTS['debug'] = str(debug)
        cfgdir = os.path.dirname(filename)
        _CONFIG_DEFAULTS['pysaml2_config'] = os.path.join(cfgdir, _CONFIG_DEFAULTS['pysaml2_config'])
        self.config = ConfigParser.ConfigParser(_CONFIG_DEFAULTS)
        if not self.config.read([filename]):
            raise ValueError("Failed loading config file {!r}".format(filename))

    @property
    def num_threads(self):
        """
        Number of worker threads to start (integer).

        EduID IdP spawns multiple threads to make use of all CPU cores in the password
        pre-hash function.
        Number of threads should probably be about 2x number of cores to 4x number of
        cores (if hyperthreading is available).
        """
        return self.config.getint(self.section, 'num_threads')

    @property
    def logdir(self):
        """
        Path to CherryPy logfiles (string). Something like '/var/log/idp' maybe.
        """
        res = self.config.get(self.section, 'logdir')
        if not res:
            res = None
        return res

    @property
    def logfile(self):
        """
        Path to application logfile. Something like '/var/log/idp/eduid_idp.log' maybe.
        """
        res = self.config.get(self.section, 'logfile')
        if not res:
            res = None
        return res

    @property
    def syslog_socket(self):
        """
        Syslog socket to log to (string). Something like '/dev/log' maybe.
        """
        res = self.config.get(self.section, 'syslog_socket')
        if not res:
            res = None
        return res

    @property
    def debug(self):
        """
        Set to True to log debug messages (boolean).
        """
        return self.config.getboolean(self.section, 'debug')

    @property
    def syslog_debug(self):
        """
        Set to True to log debug messages to syslog (also requires syslog_socket) (boolean).
        """
        return self.config.getboolean(self.section, 'syslog_debug')

    @property
    def listen_addr(self):
        """
        IP address to listen on.
        """
        return self.config.get(self.section, 'listen_addr')

    @property
    def listen_port(self):
        """
        The port the IdP authentication should listen on (integer).
        """
        return self.config.getint(self.section, 'listen_port')

    @property
    def pysaml2_config(self):
        """
        pysaml2 configuration file. Separate config file with SAML related parameters.
        """
        return self.config.get(self.section, 'pysaml2_config')

    @property
    def fticks_secret_key(self):
        """
        SAML F-TICKS user anonymization key. If this is set, the IdP will log FTICKS data
        on every login.
        """
        return self.config.get(self.section, 'fticks_secret_key')

    @property
    def fticks_format_string(self):
        """
        Get SAML F-TICKS format string.
        """
        return self.config.get(self.section, 'fticks_format_string')

    @property
    def static_dir(self):
        """
        Directory with static files to be served.
        """
        return self.config.get(self.section, 'static_dir')

    @property
    def ssl_adapter(self):
        """
        CherryPy SSL adapter class to use (must be one of cherrypy.wsgiserver.ssl_adapters)
        """
        return self.config.get(self.section, 'ssl_adapter')

    @property
    def server_cert(self):
        """
        SSL certificate filename (None == SSL disabled)
        """
        return self.config.get(self.section, 'server_cert')

    @property
    def server_key(self):
        """
        SSL private key filename (None == SSL disabled)
        """
        return self.config.get(self.section, 'server_key')

    @property
    def cert_chain(self):
        """
        SSL certificate chain filename
        """
        return self.config.get(self.section, 'cert_chain')

    @property
    def userdb_mongo_uri(self):
        """
        UserDB MongoDB connection URI (string). See MongoDB documentation for details.
        """
        return self.config.get(self.section, 'userdb_mongo_uri')

    @property
    def userdb_mongo_database(self):
        """
        UserDB database name.
        """
        return self.config.get(self.section, 'userdb_mongo_database')

    @property
    def sso_session_lifetime(self):
        """
        Lifetime of SSO session (in minutes).

        If a user has an active SSO session, they will get SAML assertions made
        without having to authenticate again (unless SP requires it through
        ForceAuthn).

        The total time a user can access a particular SP would therefor be
        this value, plus the pysaml2 lifetime of the assertion.
        """
        return self.config.getint(self.section, 'sso_session_lifetime')

    @property
    def sso_session_mongo_uri(self):
        """
        SSO session MongoDB connection URI (string). See MongoDB documentation for details.

        If not set, an in-memory SSO session cache will be used.
        """
        return self.config.get(self.section, 'sso_session_mongo_uri')

    @property
    def raven_dsn(self):
        """
        Raven DSN (string) for logging exceptions to Sentry.
        """
        return self.config.get(self.section, 'raven_dsn')

    @property
    def content_packages(self):
        """
        Get list of tuples with packages and paths to content resources, such as login.html.

        The expected format in the INI file is

            content_packages = pkg1:some/path/, pkg2:foo

        :return: list of (pkg, path) tuples
        """
        if self._parsed_content_packages:
            return self._parsed_content_packages
        value = self.config.get(self.section, 'content_packages')
        res = []
        for this in value.split(','):
            this = this.strip()
            name, _sep, path, = this.partition(':')
            res.append((name, path))
        self._parsed_content_packages = res
        return res

    @property
    def verify_request_signatures(self):
        """
        Verify request signatures, if they exist.

        This defaults to False since it is a trivial DoS to consume all the IdP:s
        CPU resources if this is set to True.
        """
        res = self.config.get(self.section, 'verify_request_signatures')
        return bool(int(res))

    @property
    def status_test_usernames(self):
        """
        Get list of usernames valid for use with the /status URL.

        If this list is ['*'], all usernames are allowed for /status.

        :return: list of usernames

        :rtype: list[string]
        """
        if self._parsed_status_test_usernames:
            return self._parsed_status_test_usernames
        value = self.config.get(self.section, 'status_test_usernames')
        res = [x.strip() for x in value.split(',')]
        self._parsed_status_test_usernames = res
        return res

    @property
    def signup_link(self):
        """
        URL (string) for use in simple templating of login.html.
        """
        return self.config.get(self.section, 'signup_link')

    @property
    def dashboard_link(self):
        """
        URL (string) for use in simple templating of forbidden.html.
        """
        return self.config.get(self.section, 'dashboard_link')

    @property
    def password_reset_link(self):
        """
        URL (string) for use in simple templating of login.html.
        """
        return self.config.get(self.section, 'password_reset_link')

    @property
    def default_language(self):
        """
        Default language code to use when looking for web pages ('en').
        """
        return self.config.get(self.section, 'default_language')

    @property
    def base_url(self):
        """
        Base URL of the IdP. The default base URL is constructed from the
        Request URI, but for example if there is a load balancer/SSL
        terminator in front of the IdP it might be required to specify
        the URL of the service.
        """
        return self.config.get(self.section, 'base_url')

    @property
    def default_eppn_scope(self):
        """
        The scope to append to any unscoped eduPersonPrincipalName
        attributes found on users in the userdb.
        """
        return self.config.get(self.section, 'default_eppn_scope')

    @property
    def authn_info_mongo_uri(self):
        """
        Authn info (failed logins etc.) MongoDB connection URI (string).
        See MongoDB documentation for details.

        If not set, Kantara authn logs will not be maintained.
        """
        return self.config.get(self.section, 'authn_info_mongo_uri')

    @property
    def max_authn_failures_per_month(self):
        """
        Disallow login for a user after N failures in a given month.

        This is said to be an imminent Kantara requirement.
        """
        return self.config.getint(self.section, 'max_authn_failures_per_month')

    @property
    def login_state_ttl(self):
        """
        Lifetime of state kept in IdP login phase.

        This is the time, in minutes, a user has to complete the login phase.
        After this time, login cannot complete because the SAMLRequest, RelayState
        and possibly other needed information will be forgotten.
        """
        return self.config.getint(self.section, 'login_state_ttl')

    @property
    def default_scoped_affiliation(self):
        """
        Add a default eduPersonScopedAffiliation if none is returned from the
        attribute manager.
        """
        return self.config.get(self.section, 'default_scoped_affiliation')

    @property
    def vccs_url(self):
        """
        URL to use with VCCS client. BCP is to have an nginx or similar on
        localhost that will proxy requests to a currently available backend
        using TLS.
        """
        return self.config.get(self.section, 'vccs_url')

    @property
    def insecure_cookies(self):
        """
        Set to True to NOT set HTTP Cookie 'secure' flag (boolean).
        """
        return self.config.getboolean(self.section, 'insecure_cookies')
