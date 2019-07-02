#!/usr/bin/env python
#
# Small CLI used to manually unlock users that have reached the Kantara imposed limit
# (such as the monitoring user after certain failures).
#
import os
import sys
import logging
from eduid_common.config.idp import IdPConfig
import eduid_idp
import eduid_idp.idp

default_config_file = '/opt/eduid/eduid-idp/etc/eduid-idp.ini'
default_debug = True


def main(myname='unlock_user', cfgfile=default_config_file, debug=default_debug):
    logger = logging.getLogger(myname)
    config = IdPConfig.init_config(debug=debug)
    authn_info_db = eduid_idp.authn.AuthnInfoStoreMDB(config.mongo_uri, logger)
    idp_userdb = eduid_idp.idp_user.IdPUserDb(logger, config)

    user = idp_userdb.lookup_user(sys.argv[1])
    info = authn_info_db.get_user_authn_info(user)

    print ('User {!r} failed logins this month before unlocking: {!r}'.format(
        user, info.failures_this_month(ts=None)))
    authn_info_db.unlock_user(user.user_id)


if __name__ == '__main__':
    try:
        progname = os.path.basename(sys.argv[0])
        if main(progname):
            sys.exit(0)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)
