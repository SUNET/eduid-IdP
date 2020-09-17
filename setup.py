#!/usr/bin/env python
#
from setuptools import setup
import os

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README')).read()

version = '0.6.0'

install_requires = [x for x in open(os.path.join(here, 'requirements.txt')).read().split('\n') if len(x) > 0]
testing_extras = [x for x in open(os.path.join(here, 'test_requirements.txt')).read().split('\n')
                  if len(x) > 0 and not x.startswith('-')]

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
