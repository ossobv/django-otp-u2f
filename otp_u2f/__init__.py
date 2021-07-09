# -*- coding: utf-8 -*-

"""
Django OTP U2F plugin for Django OTP and Kleides Multi Factor Authentication.
"""

__author__ = """Harm Geerts"""
__email__ = 'hgeerts@osso.nl'

import django

if django.VERSION < (3, 2):  # pragma: no branch
    default_app_config = 'otp_u2f.apps.OtpU2fConfig'
