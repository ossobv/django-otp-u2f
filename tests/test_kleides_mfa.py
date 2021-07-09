import json

from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory

import pytest

from kleides_mfa.registry import registry
from u2flib_host import u2f
from u2flib_host.soft import SoftU2FDevice

from otp_u2f.forms import U2fDeviceCreateForm, U2fVerifyForm
from otp_u2f.models import U2fDevice

from .factories import UserFactory


def get_form_kwargs(user=None):
    if user is None:
        user = UserFactory()
    plugin = registry.get_plugin('u2f')
    request = RequestFactory().get('/u2f/create/')
    request.session = {}
    request.user = user
    return {'plugin': plugin, 'request': request}


@pytest.mark.django_db()
def test_plugin():
    plugin = registry.get_plugin('u2f')
    assert plugin.get_create_form_class() == U2fDeviceCreateForm
    assert plugin.get_verify_form_class() == U2fVerifyForm

    user = UserFactory()
    # When a user logs in the OTP device is added as a property.
    user.otp_device = U2fDevice.objects.create(user=user)
    assert registry.user_authentication_method(user) == 'u2f'


@pytest.mark.django_db()
def test_create_form_failure():
    form_kwargs = get_form_kwargs()
    form = U2fDeviceCreateForm(**form_kwargs)
    client_data = form.data_for_client()
    assert client_data['appId'] == 'http://testserver'
    challenge = client_data['registerRequests'][0]
    assert challenge['appId'] == 'http://testserver'
    assert 'challenge' in challenge
    assert challenge['version'] == 'U2F_V2'

    form = U2fDeviceCreateForm(
        data={'name': 'Bad input', 'otp_token': 'XXX'}, **form_kwargs)
    assert not form.is_valid()
    assert 'The U2F key could not be verified.' in form.errors['__all__']


@pytest.mark.django_db()
def test_create_form_default_name(tmp_path):
    user = UserFactory()
    form_kwargs = get_form_kwargs(user)
    form = U2fDeviceCreateForm(**form_kwargs)
    challenge = form.data_for_client()['registerRequests'][0]

    soft_device = SoftU2FDevice(tmp_path / 'device.u2f')
    response = u2f.register(
        soft_device, challenge, 'http://testserver')
    form = U2fDeviceCreateForm(
        data={'name': 'U2F', 'otp_token': json.dumps(response)},
        **form_kwargs)
    assert form.is_valid()
    device = form.save()
    assert device.confirmed
    assert device.user == user
    assert device.name == 'Yubico U2F Soft Device'


@pytest.mark.django_db()
def test_verify_form(settings, tmp_path):
    settings.OTP_U2F_THROTTLE_FACTOR = 0
    user = UserFactory()
    form_kwargs = get_form_kwargs(user)

    form = U2fDeviceCreateForm(**form_kwargs)
    challenge = form.data_for_client()['registerRequests'][0]

    soft_device = SoftU2FDevice(tmp_path / 'device.u2f')
    response = u2f.register(
        soft_device, challenge, 'http://testserver')
    form = U2fDeviceCreateForm(
        data={'name': 'My Key', 'otp_token': json.dumps(response)},
        **form_kwargs)
    assert form.is_valid()
    device = form.save()
    assert device.confirmed
    assert device.user == user
    assert device.name == 'My Key'

    # Verification requests require the user to have authenticated with
    # a password but lack the django session variables the middleware
    # uses to load the user for a session.
    form_kwargs = get_form_kwargs(AnonymousUser())
    form = U2fVerifyForm(
        device=device, unverified_user=user, **form_kwargs)
    client_data = form.data_for_client()
    assert client_data['appId'] == 'http://testserver'
    assert 'challenge' in client_data
    assert len(client_data['registeredKeys']) == 1
    challenge = client_data['registeredKeys'][0]
    assert challenge['appId'] == 'http://testserver'
    assert 'challenge' in challenge
    assert 'keyHandle' in challenge
    assert challenge['version'] == 'U2F_V2'

    # Nonsense token data.
    form = U2fVerifyForm(
        device=device, unverified_user=user,
        data={'otp_token': 'XXX'}, **form_kwargs)
    assert not form.is_valid()
    assert not form.get_device()

    # Sign using a consumed challenge will fail.
    response = u2f.authenticate(
        soft_device, challenge, 'http://testserver', False)
    form = U2fVerifyForm(
        device=device, unverified_user=user,
        data={'otp_token': json.dumps(response)}, **form_kwargs)
    assert form.data_for_client()['registeredKeys'][0] != challenge
    assert not form.is_valid()
    assert not form.get_device()

    # Sign with a new challenge.
    form = U2fVerifyForm(
        device=device, unverified_user=user, **form_kwargs)
    challenge = form.data_for_client()['registeredKeys'][0]
    response = u2f.authenticate(
        soft_device, challenge, 'http://testserver', False)
    form = U2fVerifyForm(
        device=device, unverified_user=user,
        data={'otp_token': json.dumps(response)}, **form_kwargs)
    assert form.is_valid()
    assert form.get_device() == device

    # Request replay will fail.
    form = U2fVerifyForm(
        device=device, unverified_user=user,
        data={'otp_token': json.dumps(response)}, **form_kwargs)
    assert form.data_for_client()['registeredKeys'][0] != challenge
    assert not form.is_valid()
    assert not form.get_device()

    # Check that verification returns the U2F device that was used to sign the
    # challenge. This is possible because all the users U2F devices are
    # included in the challenge request for ease of use.
    form_kwargs = get_form_kwargs(user)
    form = U2fDeviceCreateForm(**form_kwargs)
    challenge = form.data_for_client()['registerRequests'][0]
    soft_device2 = SoftU2FDevice(tmp_path / 'device2.u2f')
    response = u2f.register(soft_device2, challenge, 'http://testserver')
    form = U2fDeviceCreateForm(
        data={'name': '2nd Key', 'otp_token': json.dumps(response)},
        **form_kwargs)
    assert form.is_valid()
    device2 = form.save()
    assert device2.confirmed
    assert device2.user == user
    assert device2.name == '2nd Key'

    # Initiate verification with the 1st U2F device. (GET)
    form = U2fVerifyForm(
        device=device, unverified_user=user, **form_kwargs)
    client_data = form.data_for_client()
    assert len(client_data['registeredKeys']) == 2
    challenge = form.data_for_client()['registeredKeys'][1]
    # Sign with the 2nd device.
    response = u2f.authenticate(
        soft_device2, challenge, 'http://testserver', False)
    # Continue verification with the 1st device. (POST)
    form = U2fVerifyForm(
        device=device, unverified_user=user,
        data={'otp_token': json.dumps(response)}, **form_kwargs)
    assert form.is_valid()
    # The actual device used for authentication.
    assert form.get_device() == device2
