#
# Copyright (c) 2013-2016 NORDUnet A/S
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
# Author : Fredrik Thulin <fredrik@thulin.net>
#
"""
Configuration (file) handling for eduID IdP.
"""

import os
from importlib import import_module
from typing import Optional


class IdPConfig(dict):

    def __init__(self, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)
        self.logger = kwargs.get('logger')

    def __getattribute__(self, attr: str):
        '''
        XXX Once we stop seeing the DEPRECATION WARNING's logged by this
        we can remove this method and keep config as a simple dict
        '''
        try:
            return dict.__getattribute__(self, attr)
        except AttributeError:
            pass
        if self.logger is not None:
            self.logger.warning(f'DEPRECATION WARNING: {attr} config key retrieved as attr')
        upattr = attr.upper()
        if upattr in self:
            return self.get(upattr)
        raise AttributeError('Configuration key not found')


def init_config(module: str = 'eduid_idp.settings.defaults',
                test_config: Optional[dict] = None) -> IdPConfig:
    obj = import_module(module)
    config = IdPConfig()
    for key in dir(obj):
        if key.isupper():
            config[key] = getattr(obj, key)
    if test_config is not None:
        # Load init time settings
        config.update(test_config)
    else:
        from eduid_common.config.parsers.etcd import EtcdConfigParser

        common_namespace = os.environ.get('EDUID_CONFIG_COMMON_NS', '/eduid/webapp/common/')
        common_parser = EtcdConfigParser(common_namespace)
        config.update(common_parser.read_configuration(silent=True))

        namespace = os.environ.get('EDUID_CONFIG_NS', '/eduid/webapp/idp/')
        parser = EtcdConfigParser(namespace)
        # Load optional app specific settings
        config.update(parser.read_configuration(silent=True))

    return config
