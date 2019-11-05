import json
import os
import tempfile

from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory, TestCase
from django.test.utils import override_settings

from kleides_mfa.registry import registry
from u2flib_host import u2f
from u2flib_host.soft import SoftU2FDevice

from otp_u2f.forms import U2fDeviceCreateForm, U2fVerifyForm

from .factories import UserFactory


class KleidesMfaTestCase(TestCase):
    def get_form_kwargs(self, user=None):
        if user is None:
            user = UserFactory()
        plugin = registry.get_plugin('u2f')
        request = RequestFactory().get('/u2f/create/')
        request.session = {}
        request.user = user
        return {'plugin': plugin, 'request': request}

    def test_plugin(self):
        plugin = registry.get_plugin('u2f')
        self.assertEqual(plugin.get_create_form_class(), U2fDeviceCreateForm)
        self.assertEqual(plugin.get_verify_form_class(), U2fVerifyForm)

    def test_create_form_failure(self):
        form_kwargs = self.get_form_kwargs()
        form = U2fDeviceCreateForm(**form_kwargs)
        client_data = form.data_for_client()
        self.assertEqual(client_data['appId'], 'http://testserver')
        challenge = client_data['registerRequests'][0]
        self.assertEqual(challenge['appId'], 'http://testserver')
        self.assertIn('challenge', challenge)
        self.assertEqual(challenge['version'], 'U2F_V2')

        form = U2fDeviceCreateForm(
            data={'name': 'Bad input', 'otp_token': 'XXX'}, **form_kwargs)
        self.assertFalse(form.is_valid())
        self.assertIn(
            'The U2F key could not be verified.', form.errors['__all__'])

    def test_create_form_default_name(self):
        user = UserFactory()
        form_kwargs = self.get_form_kwargs(user)
        form = U2fDeviceCreateForm(**form_kwargs)
        challenge = form.data_for_client()['registerRequests'][0]

        # The file must not exist so we cannot use NamedTemporaryFile.
        filename = tempfile.mktemp()
        try:
            soft_device = SoftU2FDevice(filename)
            response = u2f.register(
                soft_device, challenge, 'http://testserver')
            form = U2fDeviceCreateForm(
                data={'name': 'U2F', 'otp_token': json.dumps(response)},
                **form_kwargs)
            self.assertTrue(form.is_valid())
            device = form.save()
            self.assertTrue(device.confirmed)
            self.assertEqual(device.user, user)
            self.assertEqual(device.name, 'Yubico U2F Soft Device')
        finally:
            if os.path.exists(filename):
                os.unlink(filename)

    @override_settings(OTP_U2F_THROTTLE_FACTOR=0)
    def test_verify_form(self):
        user = UserFactory()
        form_kwargs = self.get_form_kwargs(user)

        form = U2fDeviceCreateForm(**form_kwargs)
        challenge = form.data_for_client()['registerRequests'][0]

        # The file must not exist so we cannot use NamedTemporaryFile.
        filename = tempfile.mktemp()
        try:
            soft_device = SoftU2FDevice(filename)
            response = u2f.register(
                soft_device, challenge, 'http://testserver')
            form = U2fDeviceCreateForm(
                data={'name': 'My Key', 'otp_token': json.dumps(response)},
                **form_kwargs)
            self.assertTrue(form.is_valid())
            device = form.save()
            self.assertTrue(device.confirmed)
            self.assertEqual(device.user, user)
            self.assertEqual(device.name, 'My Key')

            # Verification requests require the user to have authenticated with
            # a password but lack the django session variables the middleware
            # uses to load the user for a session.
            form_kwargs = self.get_form_kwargs(AnonymousUser())
            form = U2fVerifyForm(
                device=device, unverified_user=user, **form_kwargs)
            client_data = form.data_for_client()
            self.assertEqual(client_data['appId'], 'http://testserver')
            self.assertIn('challenge', client_data)
            challenge = client_data['registeredKeys'][0]
            self.assertEqual(challenge['appId'], 'http://testserver')
            self.assertIn('challenge', challenge)
            self.assertIn('keyHandle', challenge)
            self.assertEqual(challenge['version'], 'U2F_V2')

            # Nonsense token data.
            form = U2fVerifyForm(
                device=device, unverified_user=user,
                data={'otp_token': 'XXX'}, **form_kwargs)
            self.assertFalse(form.is_valid())

            # Sign using a consumed challenge will fail.
            response = u2f.authenticate(
                soft_device, challenge, 'http://testserver', False)
            form = U2fVerifyForm(
                device=device, unverified_user=user,
                data={'otp_token': json.dumps(response)}, **form_kwargs)
            self.assertNotEqual(
                form.data_for_client()['registeredKeys'][0], challenge)
            self.assertFalse(form.is_valid())

            # Sign with a new challenge.
            form = U2fVerifyForm(
                device=device, unverified_user=user, **form_kwargs)
            challenge = form.data_for_client()['registeredKeys'][0]
            response = u2f.authenticate(
                soft_device, challenge, 'http://testserver', False)
            form = U2fVerifyForm(
                device=device, unverified_user=user,
                data={'otp_token': json.dumps(response)}, **form_kwargs)
            self.assertTrue(form.is_valid())

            # Request replay will fail.
            form = U2fVerifyForm(
                device=device, unverified_user=user,
                data={'otp_token': json.dumps(response)}, **form_kwargs)
            self.assertNotEqual(
                form.data_for_client()['registeredKeys'][0], challenge)
            self.assertFalse(form.is_valid())
        finally:
            if os.path.exists(filename):
                os.unlink(filename)
