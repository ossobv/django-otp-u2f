import json
import logging

from django.db.models import F

import pytest

from u2flib_host import u2f
from u2flib_host.soft import SoftU2FDevice

from otp_u2f.models import U2fDevice, U2fDeviceClonedError

from .factories import UserFactory

APP_ID = 'https://localhost'


def sign_challenge(device, challenge):
    registered_key = challenge['registeredKeys'][0]
    key_challenge = {
        'appId': registered_key['appId'],
        'keyHandle': registered_key['keyHandle'],
        'version': registered_key['version'],
        'challenge': challenge['challenge'],
    }
    return u2f.authenticate(device, key_challenge, APP_ID, False)


def assert_verified(device, user, challenge, response, expected=True):
    actual_device, verified = U2fDevice.complete_authentication(
        user, challenge, response)
    assert actual_device == device
    assert verified is expected


@pytest.mark.django_db()
def test_enroll(caplog, settings, tmp_path):
    settings.OTP_U2F_THROTTLE_FACTOR = 0
    user = UserFactory()

    request = U2fDevice.begin_registration(user, 'https://localhost')

    soft_device = SoftU2FDevice(tmp_path / 'device.u2f')
    response = u2f.register(
        soft_device, request.data_for_client['registerRequests'][0],
        APP_ID)
    device, certificate = U2fDevice.complete_registration(
        request, response)

    u2f_device = U2fDevice.objects.create(
        user=user, name='U2F Soft device', app_id=device['appId'],
        version=device['version'], certificate=certificate,
        key_handle=device['keyHandle'], public_key=device['publicKey'],
        transports=json.dumps(device['transports']))
    assert u2f_device.confirmed

    # Note: the following tests follow the django-otp api.
    challenge = u2f_device.generate_challenge()
    # django-otp api passes tokens as strings.
    response = json.dumps(sign_challenge(soft_device, challenge))
    assert u2f_device.verify_token(response)

    # Generate another challenge
    challenge = u2f_device.generate_challenge()
    # django-otp api passes tokens as strings.
    response = json.dumps(sign_challenge(soft_device, challenge))
    assert u2f_device.verify_token(response)
    # Can't verify the same token twice
    assert not u2f_device.verify_token(response)

    # Bad user/interface input.
    assert not u2f_device.verify_token('XXX')

    # Note, the following tests follow the U2F api.
    challenge = U2fDevice.begin_authentication(user, APP_ID)
    assert_verified(None, user, challenge, 'XXX', expected=False)

    # Inactive device.
    user.u2fdevice_set.update(confirmed=False)
    response = json.dumps(sign_challenge(
        soft_device, challenge.data_for_client))
    assert_verified(None, user, challenge, response, expected=False)

    # No active keys, no challenge.
    with pytest.raises(ValueError):
        U2fDevice.begin_authentication(user, APP_ID)
    user.u2fdevice_set.update(confirmed=True)

    # Test failure throttling.
    settings.OTP_U2F_THROTTLE_FACTOR = 100
    # Invalid attempt.
    challenge = U2fDevice.begin_authentication(user, APP_ID)
    response = json.dumps(sign_challenge(
        soft_device, challenge.data_for_client))
    challenge = U2fDevice.begin_authentication(user, APP_ID)
    assert_verified(u2f_device, user, challenge, response, expected=False)
    # Throttled valid attempt.
    challenge = U2fDevice.begin_authentication(user, APP_ID)
    response = json.dumps(sign_challenge(
        soft_device, challenge.data_for_client))
    assert_verified(u2f_device, user, challenge, response, expected=False)
    settings.OTP_U2F_THROTTLE_FACTOR = 0

    # Duplicate key.
    dupe_device = user.u2fdevice_set.get()
    dupe_device.pk = None
    dupe_device.save()

    challenge = U2fDevice.begin_authentication(user, APP_ID)
    response = json.dumps(sign_challenge(
        soft_device, challenge.data_for_client))
    with caplog.at_level(logging.WARNING, logger='otp_u2f.models'):
        assert_verified(u2f_device, user, challenge, response)
    assert caplog.record_tuples == [
        ('otp_u2f.models', logging.WARNING,
            f'Removing duplicate device {u2f_device!r}')]

    # Cloned key.
    user.u2fdevice_set.update(counter=F('counter') + 1)
    challenge = U2fDevice.begin_authentication(user, APP_ID)
    response = json.dumps(sign_challenge(
        soft_device, challenge.data_for_client))
    with pytest.raises(U2fDeviceClonedError):
        U2fDevice.complete_authentication(user, challenge, response)

    # Cloned device has been deactivated.
    u2f_device = user.u2fdevice_set.get()
    assert not u2f_device.confirmed
