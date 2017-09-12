import os

import tempfile
from django.conf import settings

from django.contrib.auth import get_user_model
from django.test import TestCase

import u2flib_host.authenticate
import u2flib_host.soft
import u2flib_host.u2f

from django_otp_u2f import models


class U2FDeviceTestCase(TestCase):
    def sign_challenge(self, devices, challenge):
        for registered_key in challenge['registeredKeys']:
            key_challenge = {
                'appId': registered_key['appId'],
                'keyHandle': registered_key['keyHandle'],
                'version': registered_key['version'],
                'challenge': challenge['challenge'],
            }
            return u2flib_host.authenticate.authenticate(devices, key_challenge, settings.OTP_U2F_APP_ID, False)

    def test_enroll(self):
        user = get_user_model().objects.create()
        u2f_device = models.U2FDevice.objects.create(user=user)
        self.assertFalse(u2f_device.confirmed)

        enroll_challenge, data_for_client = u2f_device.begin_registration()

        filename = tempfile.mktemp()
        try:
            soft_device = u2flib_host.soft.SoftU2FDevice(filename)
            result = u2flib_host.u2f.register(soft_device, data_for_client['registerRequests'][0],
                                              settings.OTP_U2F_APP_ID)
            u2f_device.create_key(enroll_challenge, result)
            self.assertTrue(u2f_device.confirmed)

            challenge = u2f_device.generate_challenge()
            result = self.sign_challenge([soft_device], challenge)
            self.assertTrue(u2f_device.verify_token(result))

            # Generate another challenge
            challenge = u2f_device.generate_challenge()
            result = self.sign_challenge([soft_device], challenge)
            self.assertTrue(u2f_device.verify_token(result))
            # Can't verify the same token twice
            self.assertFalse(u2f_device.verify_token(result))

            u2f_device.u2fkey_set.get().delete()
            self.assertFalse(u2f_device.confirmed)
        finally:
            if os.path.exists(filename):
                os.unlink(filename)
