from dataclasses import replace
from urllib.parse import urlparse

from django.conf import settings
from django.contrib.sites.shortcuts import get_current_site

from fido2.cbor import decode as cbor_decode, encode as cbor_encode
from fido2.rpid import verify_rp_id
from fido2.server import Fido2Server
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import (
    AttestationConveyancePreference, AuthenticationResponse,
    PublicKeyCredentialRpEntity, UserVerificationRequirement)

from .models import U2fDevice


class Webauthn(Fido2Server):
    def __init__(self, request=None):
        self.request = request
        self.app_id = getattr(settings, 'OTP_U2F_APP_ID', None)
        self.rp_id = getattr(settings, 'OTP_U2F_RP_ID', None)
        self.rp_name = getattr(settings, 'OTP_U2F_RP_NAME', None)

        if self.rp_id is None:
            site = get_current_site(self.request)
            self.rp_id = site.domain
            self.rp_name = site.name

        if self.rp_id is None:
            site = get_current_site(self.request)
            self.rp_id = site.domain
            self.rp_name = site.name

        if self.app_id is None:
            if self.request is not None:
                self.app_id = self.request.build_absolute_uri('/')[:-1]
            else:
                self.app_id = f'https://{self.rp_id}'

        rp = PublicKeyCredentialRpEntity(id=self.rp_id, name=self.rp_name)
        super().__init__(
            rp=rp, attestation=AttestationConveyancePreference.DIRECT)
        self._app_id_server = Fido2Server(
            rp=replace(
                PublicKeyCredentialRpEntity.from_dict(rp), id=self.app_id),
            attestation=AttestationConveyancePreference.DIRECT,
            verify_origin=lambda o: verify_app_id(self.app_id, o))

    def authenticate_begin(self, user):
        return super().authenticate_begin(
            credentials=U2fDevice.get_credentials(user),
            # Disables PIN prompts but does require interactive keys to be
            # pressed.
            # https://chromium.googlesource.com/chromium/src/+/refs/heads/main/content/browser/webauth/uv_preferred.md  # NOQA
            user_verification=UserVerificationRequirement.DISCOURAGED,
            # Enable legacy U2F AppID extension to support existing devices.
            extensions={'appid': self.app_id},
        )

    def authenticate_complete(self, state, response, user):
        authentication = AuthenticationResponse.from_dict(response)
        auth_data = authentication.response.authenticator_data
        credentials = U2fDevice.get_credentials(user)
        try:
            credential = super().authenticate_complete(
                state=state, credentials=credentials, response=response)
        except ValueError:
            # Fallback to the legacy U2F AppID extension.
            credential = self._app_id_server.authenticate_complete(
                state=state, credentials=credentials, response=response)
        return (credential, auth_data)

    def register_begin(self, user):
        return super().register_begin({
            'id': str(user.pk).encode(),
            'name': user.get_username(),
            'displayName': user.get_full_name() or user.get_username()},
            credentials=U2fDevice.get_credentials(user),
            user_verification=UserVerificationRequirement.DISCOURAGED,
            # Enable legacy U2F AppID extension to exclude re-registration of
            # existing legacy registrations.
            extensions={'appidExclude': self.app_id},
        )

    def register_complete(self, state, response):
        return super().register_complete(state=state, response=response)


def verify_app_id(app_id: str, origin: str) -> bool:
    '''Checks if a FIDO U2F App ID is usable for a given origin.

    :param app_id: The App ID to validate.
    :param origin: The origin of the request.
    :return: True if the App ID is usable by the origin, False if not.
    '''
    url = urlparse(app_id)
    hostname = url.hostname
    # Note that FIDO U2F requires a secure context, i.e. an origin with https
    # scheme. However, most browsers also treat http://localhost as a secure
    # context.
    # See https://groups.google.com/a/chromium.org/g/blink-dev/c/RC9dSw-O3fE/m/E3_0XaT0BAAJ  # noqa
    if (url.scheme != 'https'
            and (url.scheme, hostname) != ('http', 'localhost')):
        return False
    if not hostname:
        return False
    return verify_rp_id(hostname, origin)


def websafe_cbor_decode(data):
    '''
    Decode base64 string to a CBOR data structure.
    '''
    return cbor_decode(websafe_decode(data))


def websafe_cbor_encode(data):
    '''
    Encode Fido data structure to a base64 encoded CBOR data structure.
    '''
    return websafe_encode(cbor_encode(data))
