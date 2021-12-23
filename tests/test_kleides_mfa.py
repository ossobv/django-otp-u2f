from base64 import urlsafe_b64decode

from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory

import pytest

from kleides_mfa.registry import registry

from otp_u2f.forms import (
    U2F_AUTHENTICATION_KEY, U2F_REGISTRATION_KEY, U2fDeviceCreateForm,
    U2fVerifyForm)
from otp_u2f.views import AuthenticateChallengeView, RegisterChallengeView

from .factories import U2fDeviceFactory, UserFactory

AUTH_CREDENTIAL = 'n8ZklynFZSmYNrICld-ShxDR64QVrov2FEmy-PaHVtVE_WCj1HpLfPMgdDBQEBK5tC7TY3U0iNGTDiWWfxLylg=='  # noqa
AUTH_PUBLIC_KEY = 'pQECAyYgASFYIKL35NsyHSsIXBqC2upUvILPoOzkuAPc2x1AT7Mkvm0fIlggJVbR-teZTDVVL7NMRLob3gZmnz0hzloFXHzOukIWIF8='  # noqa
AUTH_STATE = {
    'challenge': 'bnRQVde1p9L_W70ll7_HOxY3WMRME57IIVJURPr16Sk',
    'user_verification': None,
}
AUTH_DATA = {'otp_token': 'pGlzaWduYXR1cmVYSDBGAiEAjJz5c08jnc4kxvA1mCtd_oUfejhqbpKvp69q1CU6gqICIQDE8HZY1kwAaBOAm_WdhtLH0WUB-rd6FcDIEX477ddhQmxjcmVkZW50aWFsSWRYQJ_GZJcpxWUpmDayApXfkocQ0euEFa6L9hRJsvj2h1bVRP1go9R6S3zzIHQwUBASubQu02N1NIjRkw4lln8S8pZuY2xpZW50RGF0YUpTT05YknsidHlwZSI6IndlYmF1dGhuLmdldCIsImNoYWxsZW5nZSI6ImJuUlFWZGUxcDlMX1c3MGxsN19IT3hZM1dNUk1FNTdJSVZKVVJQcjE2U2siLCJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5vc3NvLm5pbmphOjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9cWF1dGhlbnRpY2F0b3JEYXRhWCUSXIrubSsKmsf2hd4Z9cy0vPwqgMw1u7Eoq5rF5711UQEAAAAE'}  # noqa


REG_CREDENTIAL = 'WwyEN7OnJb6KhQS_NDn4oGbiVPSuIxmKwo-77r_8nG2BKhoyQlYvuG3uS8Wa688Yi_tZNFG7mXhRaC3lUtWCnw=='  # noqa
REG_PUBLIC_KEY = 'pQECAyYgASFYIGX54GU6pZBsdbVEw6B7sGCrtKUaHmu62JTMBLd_U64_IlggERQvKwWtfZX8mvREWzv1mrTh2tsLvHlcCCH4247nZpM='  # noqa
REG_STATE = {
    'challenge': 'Mjl7qc7IRNrjUgTssfOdCm0Uz4u_94de0b-feXDAp-U',
    'user_verification': 'discouraged',
}
REG_DATA = {'otp_token': 'om5jbGllbnREYXRhSlNPTliVeyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiTWpsN3FjN0lSTnJqVWdUc3NmT2RDbTBVejR1Xzk0ZGUwYi1mZVhEQXAtVSIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Lm9zc28ubmluamE6NTAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX1xYXR0ZXN0YXRpb25PYmplY3RY4qNjZm10ZG5vbmVnYXR0U3RtdKBoYXV0aERhdGFYxBJciu5tKwqax_aF3hn1zLS8_CqAzDW7sSirmsXnvXVRQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEBbDIQ3s6clvoqFBL80OfigZuJU9K4jGYrCj7vuv_ycbYEqGjJCVi-4be5LxZrrzxiL-1k0UbuZeFFoLeVS1YKfpQECAyYgASFYIGX54GU6pZBsdbVEw6B7sGCrtKUaHmu62JTMBLd_U64_IlggERQvKwWtfZX8mvREWzv1mrTh2tsLvHlcCCH4247nZpM='}  # noqa


@pytest.fixture
def rfactory(settings):
    settings.ALLOWED_HOSTS = ['localhost.osso.ninja',  'testserver']
    return RequestFactory(SERVER_NAME='localhost.osso.ninja')


@pytest.mark.django_db()
def test_plugin():
    plugin = registry.get_plugin('u2f')
    assert plugin.get_create_form_class() == U2fDeviceCreateForm
    assert plugin.get_verify_form_class() == U2fVerifyForm

    user = UserFactory()
    # When a user logs in the OTP device is added as a property.
    user.otp_device = U2fDeviceFactory(user=user)
    assert registry.user_authentication_method(user) == 'u2f'


@pytest.mark.django_db()
def test_authenticate_challenge_view(rfactory, webauthn):
    request = rfactory.post('/u2f/auth/challenge/')
    request.session = {}
    view = AuthenticateChallengeView()
    view.setup(request)
    view.unverified_user = UserFactory()
    response = view.post(request)
    assert response.status_code == 200
    challenge = webauthn.decode(response.content + b'===')
    state = request.session[U2F_AUTHENTICATION_KEY]
    key = challenge['publicKey']
    assert key['rpId'] == 'localhost.osso.ninja'
    assert key['challenge'] == urlsafe_b64decode(state['challenge'] + '===')
    assert key['extensions'] == {'appid': 'http://localhost.osso.ninja'}


@pytest.mark.django_db()
def test_register_challenge_view(rfactory, webauthn):
    request = rfactory.post('/u2f/register/challenge/')
    request.session = {}
    request.user = UserFactory()
    response = RegisterChallengeView.as_view()(request)
    assert response.status_code == 200
    challenge = webauthn.decode(response.content + b'===')
    state = request.session[U2F_REGISTRATION_KEY]
    key = challenge['publicKey']
    assert key['rp']['id'] == 'localhost.osso.ninja'
    assert key['challenge'] == urlsafe_b64decode(state['challenge'] + '===')
    assert key['extensions'] == {'appidExclude': 'http://localhost.osso.ninja'}
    assert key['user']['id'] == str(request.user.pk).encode()
    assert key['user']['name'] == request.user.username


@pytest.mark.django_db()
def test_register_form(rfactory):
    user = UserFactory()
    plugin = registry.get_plugin('u2f')
    request = rfactory.post('/u2f/register/')
    request.session = {U2F_REGISTRATION_KEY: REG_STATE}
    request.user = user

    form = U2fDeviceCreateForm(data=REG_DATA, plugin=plugin, request=request)
    assert form.is_valid(), form.errors
    device = form.save()
    assert device.version == 'webauthn'
    assert device.aaguid.hex == '00000000000000000000000000000000'
    assert device.credential == REG_CREDENTIAL
    assert device.public_key == REG_PUBLIC_KEY
    assert device.counter == 0


@pytest.mark.django_db()
def test_register_form_failure(rfactory):
    user = UserFactory()
    plugin = registry.get_plugin('u2f')
    request = rfactory.post('/u2f/reqister/')
    request.session = {}
    request.user = user

    form = U2fDeviceCreateForm(data={}, plugin=plugin, request=request)
    assert not form.is_valid()
    assert 'This field is required.' in form.errors['otp_token']
    assert 'The registration request has expired, try again' in form.errors['__all__']  # noqa

    request.session = {U2F_REGISTRATION_KEY: REG_STATE}
    form = U2fDeviceCreateForm(
        data={'otp_token': 'xxx'}, plugin=plugin, request=request)
    assert not form.is_valid()
    assert 'The registration request is invalid' in form.errors['__all__']

    request = rfactory.get('/u2f/create/', SERVER_NAME='testserver')
    request.session = {U2F_REGISTRATION_KEY: REG_STATE}
    request.user = user
    form = U2fDeviceCreateForm(data=REG_DATA, plugin=plugin, request=request)
    assert not form.is_valid()
    assert 'Device registration failure (reason: Invalid origin in ClientData.)' in form.errors['__all__']  # noqa


@pytest.mark.django_db()
def test_authenticate_form(rfactory, settings):
    other_device = U2fDeviceFactory()
    device = U2fDeviceFactory(
        credential=AUTH_CREDENTIAL, public_key=AUTH_PUBLIC_KEY)
    user = device.user
    plugin = registry.get_plugin('u2f')
    request = rfactory.post('/u2f/authenticate/')
    request.session = {U2F_AUTHENTICATION_KEY: AUTH_STATE}
    # Verification requests require the user to have authenticated with
    # a password but lack the session variables for the session middleware
    # to load the user. They are effectively anonymous.
    request.user = AnonymousUser()

    form = U2fVerifyForm(
        data=AUTH_DATA, device=other_device, unverified_user=user,
        plugin=plugin, request=request)
    assert form.is_valid(), form.errors
    # webauth presents all known devices to the user and will return the device
    # that was used to complete authentication (started with other_device).
    assert form.device == device
    assert form.device.counter == 4


@pytest.mark.django_db()
def test_authenticate_form_failure(rfactory, settings):
    settings.OTP_U2F_THROTTLE_FACTOR = 0
    device = U2fDeviceFactory(
        credential=AUTH_CREDENTIAL, public_key=AUTH_PUBLIC_KEY, counter=5)
    user = device.user
    plugin = registry.get_plugin('u2f')
    request = rfactory.post('/u2f/authenticate/')
    request.session = {}
    # Verification requests require the user to have authenticated with
    # a password but lack the session variables for the session middleware
    # to load the user. They are effectively anonymous.
    request.user = AnonymousUser()

    # Auth with an expired challenge fails.
    form = U2fVerifyForm(
        data={}, device=device, unverified_user=user,
        plugin=plugin, request=request)
    assert not form.is_valid()
    assert 'This field is required.' in form.errors['otp_token']
    assert 'The authentication request has expired, try again' in form.errors['__all__']  # noqa

    request.session = {U2F_AUTHENTICATION_KEY: AUTH_STATE}
    # Nonsense token data.
    form = U2fVerifyForm(
        data={'otp_token': 'XXX'}, device=device, unverified_user=user,
        plugin=plugin, request=request)
    assert not form.is_valid()
    assert 'The authentication request is invalid' in form.errors['__all__']

    request.session = {U2F_AUTHENTICATION_KEY: AUTH_STATE}
    # Test authenticator counter.
    form = U2fVerifyForm(
        data=AUTH_DATA, device=device, unverified_user=user,
        plugin=plugin, request=request)
    assert not form.is_valid()
    assert not form.device.confirmed
    assert f'Device authentication failure (reason: Device appears to be cloned, expected counter > 5 but got 4 instead. The device otp_u2f.u2fdevice/{device.pk} has been disabled.)' in form.errors['__all__']  # noqa
