#!/bin/bash
#
# Install all requirements
#

set -e
set -x

#  'xmlsec1',         # needed by make-metadata.py
#  'libxml2-dev',     # needed to install pyXMLSecurity
#  'libxslt1-dev',    # needed to install pyXMLSecurity
#  'build-essential', # needed to install PyKCS11
#  'zlib1g-dev',      # needed to install pyXMLSecurity

#  libffi-dev         # needed by pysaml2
#  libssl-dev         # needed by pysaml2

apt-get update
apt-get -y install \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    xmlsec1 \
    libxml2-utils \
    libffi-dev \
    libssl-dev \
    softhsm
apt-get clean
rm -rf /var/lib/apt/lists/*

PYPI="https://pypi.nordu.net/simple/"
ping -c 1 -q pypiserver.docker && PYPI="http://pypiserver.docker:8080/simple/"

echo "#############################################################"
echo "$0: Using PyPi URL ${PYPI}"
echo "#############################################################"

/opt/eduid/bin/pip install --pre -i ${PYPI} eduid-idp-html
/opt/eduid/bin/pip install       -i ${PYPI} raven
# Temporarily install fixed version of pykcs11 until issues with 1.3.1 is fixed
/opt/eduid/bin/pip install       -i ${PYPI} pykcs11==1.3.0
/opt/eduid/bin/pip install       -i ${PYPI} pyXMLSecurity[PKCS11]
/opt/eduid/bin/pip install       -i ${PYPI} requests
/opt/eduid/bin/pip install --pre -i ${PYPI} eduid_action.tou

/opt/eduid/bin/pip freeze
