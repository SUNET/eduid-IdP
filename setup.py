#!/usr/bin/env python
#
from setuptools import setup
import os

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README')).read()

version = '0.5.5'

install_requires = [
    'eduid_userdb >= 0.4.0',
    'eduid_common[idp] >= 0.3.6b2',
    'pysaml2 == 4.6.1',
    'cherrypy == 15.0',
    'defusedxml >= 0.5.0',
    'six',
]

testing_extras = [
    'nose == 1.3.7',
    'coverage == 4.5.1',
    'WebTest == 2.0.30',
    'mock == 2.0.0',
    'nosexcover >= 1.0.11',
    'eduid_action>=0.2.1b2',
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
