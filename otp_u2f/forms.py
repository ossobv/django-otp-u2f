# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

import json

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import NameOID, load_der_x509_certificate
from django import forms
from django.utils.translation import ugettext_lazy as _

from kleides_mfa.forms import BaseVerifyForm, DeviceCreateForm
from u2flib_server.model import U2fRegisterRequest, U2fSignRequest

from .models import U2fDevice

U2F_AUTHENTICATION_KEY = 'kleides-mfa-u2f-authentication-key'
U2F_REGISTRATION_KEY = 'kleides-mfa-u2f-registration-key'


class U2fDeviceCreateForm(DeviceCreateForm):
    otp_token = forms.CharField(label=_('U2F'), widget=forms.HiddenInput())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._challenge = self._get_u2f_challenge()

    def _get_u2f_challenge(self):
        # Store the U2F challenge in the session, rotate it on unbound forms.
        if self.is_bound and U2F_REGISTRATION_KEY in self.request.session:
            challenge = self.request.session[U2F_REGISTRATION_KEY]
        else:
            challenge = U2fDevice.begin_registration(
                self.request.user, self.request.build_absolute_uri('/')[:-1])
            self.request.session[U2F_REGISTRATION_KEY] = challenge
        return U2fRegisterRequest.wrap(challenge)

    def data_for_client(self):
        # Client library expects appId in the registerRequest...
        data = self._challenge.data_for_client
        for request in data['registerRequests']:
            request['appId'] = data['appId']
        return data

    def clean(self):
        self.cleaned_data = super().clean()
        try:
            device, certificate = U2fDevice.complete_registration(
                self._challenge, json.loads(self.cleaned_data['otp_token']))
        except Exception:
            raise forms.ValidationError(
                _('The U2F key could not be verified.'))
        finally:
            if U2F_REGISTRATION_KEY in self.request.session:  # noqa: E501; pragma: no cover
                del self.request.session[U2F_REGISTRATION_KEY]

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
            except Exception:  # pragma: no cover
                pass
        return self.cleaned_data

    class Meta:
        model = U2fDevice
        fields = ('name', 'otp_token',)


class U2fVerifyForm(BaseVerifyForm):
    otp_token = forms.CharField(label=_('U2F'), widget=forms.HiddenInput())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._challenge = self._get_u2f_challenge()

    def _get_u2f_challenge(self):
        # Store the U2F challenge in the session, rotate it on unbound forms.
        if self.is_bound and U2F_AUTHENTICATION_KEY in self.request.session:
            challenge = self.request.session[U2F_AUTHENTICATION_KEY]
        else:
            challenge = U2fDevice.begin_authentication(
                self.unverified_user,
                self.request.build_absolute_uri('/')[:-1])
            self.request.session[U2F_AUTHENTICATION_KEY] = challenge
        return U2fSignRequest.wrap(challenge)

    def data_for_client(self):
        # Client library expects challenge in the registeredKeys...
        data = self._challenge.data_for_client
        for key in data['registeredKeys']:
            key['challenge'] = data['challenge']
        return data

    def clean(self):
        self.cleaned_data = super().clean()
        try:
            verified = U2fDevice.complete_authentication(
                self.unverified_user, self._challenge,
                json.loads(self.cleaned_data['otp_token']))
        except Exception:
            verified = False
        finally:
            if U2F_AUTHENTICATION_KEY in self.request.session:  # noqa: E501; pragma: no cover
                del self.request.session[U2F_AUTHENTICATION_KEY]

        if not verified:
            raise forms.ValidationError(
                _('The U2F key could not be verified.'))
        return self.cleaned_data
