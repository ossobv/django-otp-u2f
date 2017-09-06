import os

import tempfile
from django.conf import settings

from django.contrib.auth import get_user_model
from django.test import LiveServerTestCase

import u2flib_host.soft
import u2flib_host.u2f

from django_otp_u2f import models


class U2FDeviceTestCase(LiveServerTestCase):
    def test_enroll(self):
        user = get_user_model().objects.create()
        device, data_for_client = models.U2FDevice.enroll(user=user)
        self.assertIsInstance(device, models.U2FDevice)

        filename = tempfile.mktemp()
        try:
            soft_device = u2flib_host.soft.SoftU2FDevice(filename)
            result = u2flib_host.u2f.register(soft_device, data_for_client['registerRequests'][0],
                                              settings.OTP_U2F_APP_ID)
            device.bind(result)

            challenge = device.generate_challenge()
            result = u2flib_host.u2f.authenticate(soft_device, challenge, settings.OTP_U2F_APP_ID)
            self.assertTrue(device.verify_token(result))

            # Generate another challenge
            challenge = device.generate_challenge()
            result = u2flib_host.u2f.authenticate(soft_device, challenge, settings.OTP_U2F_APP_ID)
            self.assertTrue(device.verify_token(result))
            # Can't verify the same token twice
            self.assertFalse(device.verify_token(result))

        finally:
            if os.path.exists(filename):
                os.unlink(filename)
