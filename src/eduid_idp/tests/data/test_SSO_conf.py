import os

from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, BINDING_SOAP
from saml2.saml import NAME_FORMAT_URI, NAMEID_FORMAT_PERSISTENT, NAMEID_FORMAT_TRANSIENT

try:
    from saml2.sigver import get_xmlsec_binary
except ImportError:
    get_xmlsec_binary = None

if get_xmlsec_binary:
    xmlsec_path = get_xmlsec_binary(["/opt/local/bin"])
else:
    xmlsec_path = '/usr/bin/xmlsec1'

_hostname = 'unittest-idp.example.edu'
BASE = "https://{!s}".format(_hostname)

here = os.path.dirname(__file__)
key_path = os.path.join(here, 'idp-public-snakeoil.key')
cert_path = os.path.join(here, 'idp-public-snakeoil.pem')

attrmaps_path = os.path.join(here, '../../../attributemaps')
sp_metadata_path = os.path.join(here, 'sp_metadata.xml')


CONFIG = {
    "entityid": "%s/idp.xml" % BASE,
    "description": "eduID UNITTEST identity provider",
    "service": {
        "idp": {
            "name": "eduID UNITTEST IdP",
            "scope": ["eduid.example.edu"],
            "endpoints": {
                "single_sign_on_service": [
                    ("%s/sso/redirect" % BASE, BINDING_HTTP_REDIRECT),
                    ("%s/sso/post" % BASE, BINDING_HTTP_POST),
                ],
                "single_logout_service": [
                    ("%s/slo/soap" % BASE, BINDING_SOAP),
                    ("%s/slo/post" % BASE, BINDING_HTTP_POST),
                    ("%s/slo/redirect" % BASE, BINDING_HTTP_REDIRECT),
                ],
            },
            "policy": {
                "default": {
                    "lifetime": {"minutes": 5},
                    "attribute_restrictions": None,  # means all I have
                    "name_form": NAME_FORMAT_URI,
                    "nameid_format": NAMEID_FORMAT_PERSISTENT,
                    # "entity_categories": ["swamid", "edugain"]
                    "entity_categories": [],
                },
            },
            "name_id_format": [NAMEID_FORMAT_TRANSIENT, NAMEID_FORMAT_PERSISTENT],
        },
    },
    "debug": 1,
    "metadata": {"local": [sp_metadata_path]},
    "attribute_map_dir": attrmaps_path,
    "key_file": key_path,
    "cert_file": cert_path,
    "xmlsec_binary": xmlsec_path,
    "organization": {
        "display_name": "eduID UNITTEST",
        "name": "eduID UNITTEST",
        "url": "http://www.eduid.se/",
    },
}
