import json
import os
import tempfile

from django.db.models import F
from django.test import TestCase
from django.test.utils import override_settings

from u2flib_host import u2f
from u2flib_host.soft import SoftU2FDevice

from otp_u2f.models import U2fDevice, U2fDeviceClonedError

from .factories import UserFactory

APP_ID = 'https://localhost'


@override_settings(OTP_U2F_THROTTLE_FACTOR=0)
class U2FDeviceTestCase(TestCase):
    def sign_challenge(self, device, challenge):
        registered_key = challenge['registeredKeys'][0]
        key_challenge = {
            'appId': registered_key['appId'],
            'keyHandle': registered_key['keyHandle'],
            'version': registered_key['version'],
            'challenge': challenge['challenge'],
        }
        return u2f.authenticate(
            device, key_challenge, APP_ID, False)

    def test_enroll(self):
        user = UserFactory()

        request = U2fDevice.begin_registration(
            user, 'https://localhost')

        filename = tempfile.mktemp()
        try:
            soft_device = SoftU2FDevice(filename)
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
            self.assertTrue(u2f_device.confirmed)

            # Note: the following tests follow the django-otp api.
            challenge = u2f_device.generate_challenge()
            # django-otp api passes tokens as strings.
            response = json.dumps(
                self.sign_challenge(soft_device, challenge))
            self.assertTrue(u2f_device.verify_token(response))

            # Generate another challenge
            challenge = u2f_device.generate_challenge()
            # django-otp api passes tokens as strings.
            response = json.dumps(
                self.sign_challenge(soft_device, challenge))
            self.assertTrue(u2f_device.verify_token(response))
            # Can't verify the same token twice
            self.assertFalse(u2f_device.verify_token(response))

            # Bad user/interface input.
            self.assertFalse(u2f_device.verify_token('XXX'))

            # Note, the following tests follow the U2F api.
            challenge = U2fDevice.begin_authentication(user, APP_ID)
            self.assertFalse(
                U2fDevice.complete_authentication(user, challenge, 'XXX'))

            # Inactive device.
            user.u2fdevice_set.update(confirmed=False)
            response = json.dumps(
                self.sign_challenge(soft_device, challenge.data_for_client))
            self.assertFalse(
                U2fDevice.complete_authentication(user, challenge, response))

            # No active keys, no challenge.
            with self.assertRaises(ValueError):
                U2fDevice.begin_authentication(user, APP_ID)
            user.u2fdevice_set.update(confirmed=True)

            # Test failure throttling.
            with override_settings(OTP_U2F_THROTTLE_FACTOR=100):
                # Invalid attempt.
                challenge = U2fDevice.begin_authentication(user, APP_ID)
                response = json.dumps(self.sign_challenge(
                    soft_device, challenge.data_for_client))
                challenge = U2fDevice.begin_authentication(user, APP_ID)
                self.assertFalse(U2fDevice.complete_authentication(
                    user, challenge, response))
                # Throttled valid attempt.
                challenge = U2fDevice.begin_authentication(user, APP_ID)
                response = json.dumps(self.sign_challenge(
                    soft_device, challenge.data_for_client))
                self.assertFalse(U2fDevice.complete_authentication(
                    user, challenge, response))

            # Duplicate key.
            dupe_device = user.u2fdevice_set.get()
            dupe_device.pk = None
            dupe_device.save()

            challenge = U2fDevice.begin_authentication(user, APP_ID)
            response = json.dumps(
                self.sign_challenge(soft_device, challenge.data_for_client))
            with self.assertLogs('otp_u2f.models', level='WARNING') as cm:
                self.assertTrue(
                    U2fDevice.complete_authentication(
                        user, challenge, response))
                self.assertTrue(cm.output[0].startswith(
                    'WARNING:otp_u2f.models:Removing duplicate device'))

            # Cloned key.
            user.u2fdevice_set.update(counter=F('counter') + 1)
            challenge = U2fDevice.begin_authentication(user, APP_ID)
            response = json.dumps(
                self.sign_challenge(soft_device, challenge.data_for_client))
            with self.assertRaises(U2fDeviceClonedError):
                U2fDevice.complete_authentication(user, challenge, response)

            # Cloned device has been deactivated.
            u2f_device = user.u2fdevice_set.get()
            self.assertFalse(u2f_device.confirmed)
        finally:
            if os.path.exists(filename):
                os.unlink(filename)
