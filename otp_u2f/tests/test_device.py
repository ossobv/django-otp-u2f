import json
import os
import tempfile

from django.contrib.auth import get_user_model
from django.test import TestCase

import u2flib_host.authenticate
import u2flib_host.soft
import u2flib_host.u2f

from otp_u2f.models import U2fDevice


class U2FDeviceTestCase(TestCase):
    def sign_challenge(self, devices, challenge):
        for registered_key in challenge['registeredKeys']:
            key_challenge = {
                'appId': registered_key['appId'],
                'keyHandle': registered_key['keyHandle'],
                'version': registered_key['version'],
                'challenge': challenge['challenge'],
            }
            return u2flib_host.authenticate.authenticate(
                    devices, key_challenge, 'https://localhost', False)

    def test_enroll(self):
        user = get_user_model().objects.create()

        request = U2fDevice.begin_registration(
            user, 'https://localhost')

        filename = tempfile.mktemp()
        try:
            soft_device = u2flib_host.soft.SoftU2FDevice(filename)
            response = u2flib_host.u2f.register(
                soft_device, request.data_for_client['registerRequests'][0],
                'https://localhost')
            device, certificate = U2fDevice.complete_registration(
                request, response)

            u2f_device = U2fDevice.objects.create(
                user=user, name='U2F Soft device', app_id=device['appId'],
                version=device['version'], certificate=certificate,
                key_handle=device['keyHandle'], public_key=device['publicKey'],
                transports=json.dumps(device['transports']))
            self.assertTrue(u2f_device.confirmed)

            challenge = u2f_device.generate_challenge()
            # django-otp api passes tokens as strings.
            response = json.dumps(
                self.sign_challenge([soft_device], challenge))
            self.assertTrue(u2f_device.verify_token(response))

            # Generate another challenge
            challenge = u2f_device.generate_challenge()
            # django-otp api passes tokens as strings.
            response = json.dumps(
                self.sign_challenge([soft_device], challenge))
            self.assertTrue(u2f_device.verify_token(response))
            # Can't verify the same token twice
            self.assertFalse(u2f_device.verify_token(response))
        finally:
            if os.path.exists(filename):
                os.unlink(filename)
