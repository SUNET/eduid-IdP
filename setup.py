#!/usr/bin/env python
#
from setuptools import setup
import os

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README')).read()

version = '0.5.3b1'

install_requires = [
    'eduid_userdb >= 0.3.0',
    'eduid_common[idp] >= 0.2.1b4',

    'pysaml2 == 4.4.0',
    'cherrypy == 3.2.4',
    'defusedxml >= 0.5.0',
    'six',
]

testing_extras = [
    'nose == 1.2.1',
    'coverage == 3.6',
    'WebTest == 2.0.18',
    'mock == 1.0.1',
    'nosexcover == 1.0.8',
    'eduid_actions>=0.1.0',
    'eduid_action.tou',
    'eduid_action.mfa >= 0.0.2',
]

setup(name='eduid_idp',
      version=version,
      description='eduID SAML frontend IdP',
      long_description=README,
      classifiers=[
        # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
        ],
      keywords='eduID SAML',
      author='Fredrik Thulin',
      author_email='fredrik@thulin.net',
      license='BSD',
      packages=['eduid_idp',
                'eduid_idp.scripts',
                ],
      package_dir = {'': 'src'},
      #include_package_data=True,
      #package_data = { },
      zip_safe=False,
      install_requires=install_requires,
      extras_require={
          'testing': testing_extras,
      },
      entry_points={
          'console_scripts': ['eduid_idp=eduid_idp.idp:main',
                              'eduid_unlock_user=eduid_idp.scripts.unlock_user:main',
                              ]
      }
      )
