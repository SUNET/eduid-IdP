from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_SOAP
from saml2.saml import NAME_FORMAT_URI
from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2.saml import NAMEID_FORMAT_PERSISTENT

_hostname = 'unittest-idp.example.edu'
BASE = "https://{!s}".format(_hostname)

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
                    ("%s/slo/redirect" % BASE, BINDING_HTTP_REDIRECT)
                ],
            },
            "policy": {
                "default": {
                    "lifetime": {"minutes": 5},
                    "attribute_restrictions": None,  # means all I have
                    "name_form": NAME_FORMAT_URI,
                    "nameid_format": NAMEID_FORMAT_PERSISTENT,
                    #"entity_categories": ["swamid", "edugain"]
                    "entity_categories": [],
                },
            },
            "name_id_format": [NAMEID_FORMAT_TRANSIENT,
                               NAMEID_FORMAT_PERSISTENT],
            #"metadata": {"local": []},
        },
    },
    "debug": 1,
    "organization": {
        "display_name": "eduID UNITTEST",
        "name": "eduID UNITTEST",
        "url": "http://www.eduid.se/",
    },
}
