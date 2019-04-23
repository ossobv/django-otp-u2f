#!/usr/bin/env python
import os.path
from distutils.core import setup


if __name__ == '__main__':
    here = os.path.dirname(__file__)
    os.chdir(here or '.')

    with open('README.md') as fp:
        readme = fp.read()

    setup(
        name='django-otp-u2f',
        version='0.1',
        data_files=[
            ('share/doc/django-otp-u2f', ['README.md']),
        ],
        packages=['django_otp_u2f', 'django_otp_u2f.migrations'],
        package_data={},
        description='django-otp device implementation for U2F',
        long_description=readme,
        author='Harm Geerts',
        author_email='hgeerts@osso.nl',
        url='https://github.com/ossobv/django-otp-u2f/',
        license='GPLv3+',
        platforms=['linux'],
        classifiers=[
            'Development Status :: 4 - Beta',
            'Environment :: Web Environment',
            'Framework :: Django',
            'Framework :: Django :: 1.8',
            'Framework :: Django :: 1.10',
            'Framework :: Django :: 1.11',
            'Framework :: Django :: 2.1',
            'Framework :: Django :: 2.2',
            'Intended Audience :: System Administrators',
            ('License :: OSI Approved :: GNU General Public License v3 '
             'or later (GPLv3+)'),
            'Operating System :: POSIX :: Linux',
            'Programming Language :: Python',
            'Programming Language :: Python :: 2.7',
            'Programming Language :: Python :: 3.4',
            'Programming Language :: Python :: 3.5',
            'Programming Language :: Python :: 3.6',
            ('Topic :: System :: Systems Administration :: '
             'Authentication/Directory'),
        ],
        install_requires=[
            'django-otp',
            'python-u2flib-server',
        ],
    )
