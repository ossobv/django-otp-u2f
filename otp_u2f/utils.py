from base64 import urlsafe_b64decode, urlsafe_b64encode

from django.conf import settings
from django.contrib.sites.shortcuts import get_current_site
from django.utils.functional import cached_property

from fido2.cbor import decode as cbor_decode, encode as cbor_encode
from fido2.client import ClientData
from fido2.ctap2 import AttestationObject, AuthenticatorData
from fido2.server import U2FFido2Server
from fido2.webauthn import (
    PublicKeyCredentialRpEntity, UserVerificationRequirement)

from .models import U2fDevice


class Webauthn(U2FFido2Server):
    def __init__(self, request=None):
        self.request = request

    @cached_property
    def server(self):
        rp_id = getattr(settings, 'OTP_U2F_RP_ID', None)
        rp_name = getattr(settings, 'OTP_U2F_RP_NAME', None)
        app_id = getattr(settings, 'OTP_U2F_APP_ID', None)

        if rp_id is None:
            site = get_current_site(self.request)
            rp_id = site.domain
            rp_name = site.name

        if app_id is None:
            if self.request is not None:
                app_id = self.request.build_absolute_uri('/')[:-1]
            else:
                app_id = f'https://{rp_id}'

        return U2FFido2Server(
            app_id, rp=PublicKeyCredentialRpEntity(rp_id, rp_name),
            attestation='direct')

    @property
    def rp_id(self):
        return self.server.rp.id

    def authenticate_begin(self, user):
        return self.server.authenticate_begin(
            credentials=U2fDevice.get_credentials(user),
            # Disables PIN prompts but does require interactive keys to be
            # pressed.
            # https://chromium.googlesource.com/chromium/src/+/refs/heads/main/content/browser/webauth/uv_preferred.md  # NOQA
            user_verification=UserVerificationRequirement.DISCOURAGED,
        )

    def authenticate_complete(self, state, data, user):
        auth_data = AuthenticatorData(data['authenticatorData'])
        credential = self.server.authenticate_complete(
            state, credentials=U2fDevice.get_credentials(user),
            credential_id=data['credentialId'],
            client_data=ClientData(data['clientDataJSON']),
            auth_data=auth_data,
            signature=data['signature'])
        return (credential, auth_data)

    def register_begin(self, user):
        return self.server.register_begin({
            'id': str(user.pk).encode(),
            'name': user.get_username(),
            'display_name': user.get_full_name() or user.get_username()},
            credentials=U2fDevice.get_credentials(user),
            user_verification=UserVerificationRequirement.DISCOURAGED,
        )

    def register_complete(self, state, data):
        return self.server.register_complete(
            state, client_data=ClientData(data['clientDataJSON']),
            attestation_object=AttestationObject(data['attestationObject']))

    def decode(self, data):
        '''
        Decode base64 string to a CBOR data structure.
        '''
        return cbor_decode(urlsafe_b64decode(data))

    def encode(self, data):
        '''
        Encode Fido data structure to a base64 encoded CBOR data structure.
        '''
        return urlsafe_b64encode(cbor_encode(data)).decode()
