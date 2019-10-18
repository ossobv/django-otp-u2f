#!/usr/bin/env python
import os.path
from setuptools import find_packages, setup

with open('README.md') as fp:
    readme = fp.read()

setup(
    name='django-otp-u2f',
    version='0.1.0',
    data_files=[
        ('share/doc/django-otp-u2f', ['README.md']),
    ],
    packages=find_packages(exclude=('tests',)),
    include_package_data=True,
    description='django-otp device implementation for U2F',
    long_description=readme,
    author='Harm Geerts',
    author_email='hgeerts@osso.nl',
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*',
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
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.7',
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
    test_require=[
        'python-u2flib-host',
    ],
    license="GNU General Public License v3",
)
