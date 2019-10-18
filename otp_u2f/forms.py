# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

import json

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import NameOID, load_der_x509_certificate
from django import forms
from django.utils.translation import ugettext_lazy as _
from kleides_mfa.forms import DeviceCreateForm

from .models import U2fDevice

U2F_SESSION_KEY = 'kleides-mfa-u2f-key'


class U2fDeviceCreateForm(DeviceCreateForm):
    otp_token = forms.CharField(label=_('U2F'), widget=forms.HiddenInput())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Store the U2F challenge in the session, rotate it on unbound forms.
        if self.is_bound and U2F_SESSION_KEY in self.request.session:
            self._challenge = self.request.session[U2F_SESSION_KEY]
        else:
            self._challenge = self._get_u2f_challenge()
            self.request.session[U2F_SESSION_KEY] = self._challenge

    def _get_u2f_challenge(self):
        challenge = U2fDevice.begin_registration(
            self.request.user, self.request.build_absolute_uri('/')[:-1])
        # Client library expects appId in the request.
        # challenge['appId'] = challenge['appId'].replace(':8000', '')
        for request in challenge['registerRequests']:
            request['appId'] = challenge['appId']
        return challenge

    def data_for_client(self):
        return self._challenge.data_for_client

    def clean(self):
        self.cleaned_data = super().clean()
        try:
            device, certificate = U2fDevice.complete_registration(
                self._challenge, json.loads(self.cleaned_data['otp_token']))
        except Exception:
            raise forms.ValidationError(
                _('The U2F key could not be verified.'))

        self.instance.app_id = device['appId']
        self.instance.version = device['version']
        self.instance.certificate = certificate
        self.instance.key_handle = device['keyHandle']
        self.instance.public_key = device['publicKey']
        self.instance.transports = json.dumps(device['transports'])

        # Replace name if it has not changed from the initial value with the
        # name from the certificate which may include a better identifier.
        if 'name' not in self.changed_data:
            try:
                cert = load_der_x509_certificate(
                    certificate, default_backend())
                self.cleaned_data['name'] = (
                    cert.subject.get_attributes_for_oid(
                        NameOID.COMMON_NAME)[0].value)
            except Exception:
                pass
        return self.cleaned_data

    def save(self, *args, **kwargs):
        try:
            return super().save(*args, **kwargs)
        finally:
            if U2F_SESSION_KEY in self.request.session:
                del self.request.session[U2F_SESSION_KEY]

    class Meta:
        model = U2fDevice
        fields = ('name', 'otp_token',)
