import json
import logging

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import SuspiciousOperation
from django.db.models import CharField, F, PositiveIntegerField, TextField
from django.utils import timezone

from django_otp.models import Device, ThrottlingMixin

from u2flib_server.model import DeviceRegistration, SignResponse
from u2flib_server.u2f import (begin_registration, begin_authentication,
                               complete_registration, complete_authentication)

log = logging.getLogger(__name__)


U2F_REQUEST_TIMEOUT = 300


class U2fDeviceClonedError(SuspiciousOperation):
    pass


class U2fDevice(ThrottlingMixin, Device):
    app_id = CharField(max_length=100)
    version = CharField(max_length=16)
    certificate = TextField()
    key_handle = TextField()
    public_key = TextField()
    transports = TextField(default='[]')
    counter = PositiveIntegerField(default=0)

    # django-otp api
    def generate_challenge(self):
        request = U2fDevice.begin_authentication(self.user, self.app_id)
        cache.set(request['challenge'], request, U2F_REQUEST_TIMEOUT)
        return request.data_for_client

    def verify_token(self, token):
        '''
        Warning, the django-otp api does not allow associating challenges with
        a particular session. As a result anyone with the challenge is able to
        authenticate with this device.
        Because U2F is a hardware component this is an acceptable risk for most
        use cases. If you really care about this you should authenticate to
        each specific device like django-otp recommends.
        '''
        try:
            response = SignResponse.wrap(json.loads(token))
        except ValueError:
            return False
        request = cache.get(response.clientData['challenge'])
        if request is None:
            return False
        cache.delete(response.clientData['challenge'])
        return U2fDevice.complete_authentication(self.user, request, response)
    # /django-otp api

    def get_throttle_factor(self):
        return getattr(settings, 'OTP_U2F_THROTTLE_FACTOR', 1)

    @classmethod
    def begin_registration(cls, user, app_id):
        """
        Start registering a U2F security key.

        :return: request
        """
        return begin_registration(
            app_id, [key.as_device_registration()
                     for key in cls.objects.filter(user=user, confirmed=True)])

    @classmethod
    def complete_registration(cls, request, response):
        """
        Complete registering a U2F security key.

        :return: DeviceRegistration, certificate
        """
        response['version'] = 'U2F_V2'
        return complete_registration(request, response)

    @classmethod
    def begin_authentication(cls, user, app_id):
        """
        Start authenticating a U2F security key.

        :return: request
        """
        return begin_authentication(
            app_id, [key.as_device_registration()
                     for key in cls.objects.filter(user=user, confirmed=True)])

    @classmethod
    def complete_authentication(cls, user, request, response):
        """
        Complete authenticating a U2F security key.

        :return: boolean
        """
        try:
            response = SignResponse.wrap(response)
        except ValueError:
            return False

        queryset = cls.objects.filter(
            user=user, key_handle=response['keyHandle'], confirmed=True)
        try:
            device = queryset.get()
        except cls.DoesNotExist:
            return False
        except cls.MultipleObjectsReturned:
            # This should never happen because all the users keys are included
            # in the registration and the U2F client should not try to register
            # the same key twice. (At least chrome doesn't)
            for device in queryset.order_by('id')[1:]:
                log.warning('Removing duplicate device %r', device)
                device.delete()
            device = queryset.get()

        if not device.verify_is_allowed()[0]:
            return False

        try:
            _device, counter, _presence = complete_authentication(
                request, response)
        except ValueError:
            queryset.update(
                throttling_failure_timestamp=timezone.now(),
                throttling_failure_count=F('throttling_failure_count') + 1
            )
            return False

        n = queryset.filter(counter__lt=counter).update(
            throttling_failure_timestamp=None, throttling_failure_count=0,
            counter=counter)
        if n == 0:
            queryset.update(
                confirmed=False,
                throttling_failure_timestamp=timezone.now(),
                throttling_failure_count=F('throttling_failure_count') + 1,
            )
            raise U2fDeviceClonedError(
                'U2F appears to be cloned, expected counter > {} but got {} '
                'instead. The device {} has been disabled.'.format(
                    device.counter, counter, device.persistent_id))

        return True

    def as_device_registration(self):
        return DeviceRegistration(
            appId=self.app_id, version=self.version, keyHandle=self.key_handle,
            publicKey=self.public_key, transports=json.loads(self.transports))
