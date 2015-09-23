import os
import json
import pprint

import eduid_idp


__author__ = 'ft'


def enroll(logger, config, start_response):
    """
    Display the U2F token registration page.

    :param logger: logging logger
    :param config: IdP configuration data
    :param start_response: WSGI-like start_response callable

    :type logger: logging.Logger
    :type config: IdPConfig

    :rtype: string
    """

    assert isinstance(config, eduid_idp.config.IdPConfig)

    challenge = os.urandom(config.u2f_challenge_bytes).encode('hex')
    data = json.dumps({"authenticateRequests": [],
                       "registerRequests": [{"challenge": challenge,
                                             "version": "U2F_V2",
                                             "appId": config.u2f_appId,
                                             }]
                       })

    argv = {
        'action': '/u2f/finishRegistration',
        'data': data,
        'username': 'hejhej',
        'failcount': '0',
        'alert_msg': 'no alert',
    }

    logger.debug("U2F registration page HTML substitution arguments :\n{!s}".format(pprint.pformat(argv)))

    # Look for login page in user preferred language
    content = eduid_idp.mischttp.localized_resource(start_response, 'u2f_register.html', config, logger)
    if not content:
        raise eduid_idp.error.NotFound()

    # apply simplistic HTML formatting to template in 'res'
    return content.format(**argv)


def finishRegistration(logger, config, start_response):
    """
    :param logger: logging logger
    :param config: IdP configuration data
    :param start_response: WSGI-like start_response callable

    :type logger: logging.Logger
    :type config: IdPConfig

    :rtype: string
    """
    post = _unpack_post(logger)
    logger.debug("U2F enroll POST:\n{!s}".format(pprint.pformat(post)))


def authenticate(logger, config, start_response):
    post = _unpack_post(logger)
    logger.debug("U2F authenticate POST:\n{!s}".format(pprint.pformat(post)))


def _unpack_post(logger):
    """
    Unpack POSTed parameters.

    :return: query parameters as dict
    :rtype: dict
    """
    info = eduid_idp.mischttp.get_post()
    logger.debug("U2F unpack_post:: %s" % info)
    try:
        return dict([(k, v) for k, v in info.items()])
    except AttributeError:
        return None
