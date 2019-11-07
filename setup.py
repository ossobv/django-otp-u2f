#!/usr/bin/env python
import os.path
from setuptools import find_packages, setup

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

setup(
    name='django-otp-u2f',
    version='0.1.2',
    packages=find_packages(include=['otp_u2f', 'otp_u2f.*']),
    include_package_data=True,
    description='django-otp device implementation for U2F',
    long_description=readme + '\n\n' + history,
    author='Harm Geerts',
    author_email='hgeerts@osso.nl',
    python_requires='>=3.5, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*',
    url='https://github.com/ossobv/django-otp-u2f/',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Environment :: Web Environment',
        'Natural Language :: English',
        'Framework :: Django',
        'Framework :: Django :: 2.1',
        'Framework :: Django :: 2.2',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        ('Topic :: System :: Systems Administration :: '
         'Authentication/Directory'),
    ],
    install_requires=[
        'django-otp',
        'python-u2flib-server',
    ],
    license="GNU General Public License v3",
)
