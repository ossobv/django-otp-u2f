# -*- coding: utf-8 -*-

"""
Django OTP U2F plugin for Django OTP and Kleides Multi Factor Authentication.
"""

__author__ = """Harm Geerts"""
__email__ = 'hgeerts@osso.nl'

# Opt out of the new json friendly mappings and values.
import fido2.features
fido2.features.webauthn_json_mapping.enabled = False
