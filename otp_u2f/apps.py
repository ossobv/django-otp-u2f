# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

from django.apps import AppConfig, apps


class OtpU2fConfig(AppConfig):
    name = 'otp_u2f'
    verbose_name = 'Django OTP U2F'

    def ready(self):
        # Check if known devices are installed and register them as plugins.
        if apps.is_installed('kleides_mfa'):
            from kleides_mfa.registry import registry
            from .models import U2fDevice
            from .forms import U2fDeviceCreateForm
            registry.register(
                'U2F', U2fDevice, create_form=U2fDeviceCreateForm,
                show_create_button=False)
