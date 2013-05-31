#
# Copyright (c) 2013 NORDUnet A/S
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

_CONFIG_DEFAULTS = {'debug': False, # overwritten in IdPConfig.__init__()
                    'num_threads': '8',
                    'logdir': None,
                    'logfile': None,
                    'syslog': '1',	# '1' for on, '0' for off
                    'listen_addr': '0.0.0.0',
                    'listen_port': '8088',
                    'pysaml2_config': 'idp_conf.py', # path prepended in IdPConfig.__init__()
                    'static_dir': None,
                    'ssl_adapter': 'builtin',  # one of cherrypy.wsgiserver.ssl_adapters
                    'server_cert': None,  # SSL cert filename
                    'server_key': None,   # SSL key filename
                    'cert_chain': None,   # SSL certificate chain filename, or None
                    'userdb_mongo_uri': None,
                    'userdb_mongo_database': None,
                    }

_CONFIG_SECTION = 'eduid_idp'

class IdPConfig():

    def __init__(self, filename, debug):
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
    def syslog(self):
        """
        Log to syslog or not.
        """
        res = self.config.get(self.section, 'syslog')
        return bool(int(res))

    @property
    def debug(self):
        """
        Set to True to log debug messages (boolean).
        """
        return self.config.getboolean(self.section, 'debug')

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
