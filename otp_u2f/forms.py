from json import loads
from uuid import UUID

from django import forms
from django.utils.translation import gettext_lazy as _

from fido2.utils import websafe_encode
from fido2.webauthn import AuthenticationResponse, RegistrationResponse
from kleides_mfa.forms import BaseVerifyForm, DeviceCreateForm

from .models import DeviceClonedError, U2fDevice
from .utils import Webauthn, websafe_cbor_encode

U2F_AUTHENTICATION_KEY = 'kleides-mfa-u2f-authentication-key'
U2F_REGISTRATION_KEY = 'kleides-mfa-u2f-registration-key'


class U2fDeviceCreateForm(DeviceCreateForm):
    otp_token = forms.CharField(label=_('U2F'), widget=forms.HiddenInput())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._webauthn = Webauthn(self.request)
        self._state = self.request.session.pop(U2F_REGISTRATION_KEY, None)

    def clean(self):
        super().clean()

        data = self.clean_input()
        try:
            authenticator_data = self._webauthn.register_complete(
                self._state, data)
        except Exception as e:
            raise forms.ValidationError(
                _('Device registration failure (reason: {})').format(e))
        finally:
            if U2F_REGISTRATION_KEY in self.request.session:  # noqa: E501; pragma: no cover
                del self.request.session[U2F_REGISTRATION_KEY]

        credential_data = authenticator_data.credential_data
        self.instance.rp_id = self._webauthn.rp_id
        self.instance.version = 'webauthn'
        self.instance.aaguid = UUID(bytes=credential_data.aaguid)
        self.instance.credential = websafe_encode(
            credential_data.credential_id)
        self.instance.public_key = websafe_cbor_encode(
            credential_data.public_key)
        self.instance.counter = authenticator_data.counter

    def clean_input(self):
        if self._state is None:
            raise forms.ValidationError(
                _('The registration request has expired, try again'))

        try:
            data = loads(self.cleaned_data['otp_token'])
        except (TypeError, ValueError):
            raise forms.ValidationError(
                _('The registration request is invalid'))

        try:
            return RegistrationResponse.from_dict(data)
        except (KeyError, TypeError, ValueError):
            raise forms.ValidationError(
                _('The registration request is invalid'))

    class Meta:
        model = U2fDevice
        fields = ('name', 'otp_token',)


class U2fVerifyForm(BaseVerifyForm):
    otp_token = forms.CharField(label=_('U2F'), widget=forms.HiddenInput())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._webauthn = Webauthn(self.request)
        self._state = self.request.session.pop(U2F_AUTHENTICATION_KEY, None)

    def clean(self):
        super().clean()

        data = self.clean_input()
        self.device = self.clean_device(data)

        try:
            credential, authenticator = self._webauthn.authenticate_complete(
                self._state, data, self.unverified_user)
        except ValueError as e:
            self.device.increment_failure_counter()
            raise forms.ValidationError(
                _('Device authentication failure (reason: {})').format(e))

        try:
            self.device.update_usage_counter(authenticator.counter)
        except DeviceClonedError as e:
            raise forms.ValidationError(
                _('Device authentication failure (reason: {})').format(e))

    def clean_input(self):
        if self._state is None:
            raise forms.ValidationError(
                _('The authentication request has expired, try again'))

        try:
            data = loads(self.cleaned_data['otp_token'])
        except (TypeError, ValueError):
            raise forms.ValidationError(
                _('The authentication request is invalid'))

        try:
            return AuthenticationResponse.from_dict(data)
        except (KeyError, TypeError, ValueError):
            raise forms.ValidationError(
                _('The registration request is invalid'))

    def clean_device(self, data):
        try:
            device = U2fDevice.get_device(
                self.unverified_user, data['id'])
        except (KeyError, U2fDevice.DoesNotExist):
            raise forms.ValidationError(_('The device is not available'))

        if not device.verify_is_allowed()[0]:
            raise forms.ValidationError(_('The device is not available'))

        return device
