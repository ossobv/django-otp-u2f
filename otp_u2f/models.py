import json
import logging

from django.core.cache import cache
from django.db import models
from django_otp.models import Device

from u2flib_server.model import DeviceRegistration, SignResponse
from u2flib_server.u2f import (begin_registration, begin_authentication,
                               complete_registration, complete_authentication)

log = logging.getLogger(__name__)


U2F_REQUEST_TIMEOUT = 300


class U2fDevice(Device):
    app_id = models.CharField(max_length=100)
    version = models.CharField(max_length=16)
    certificate = models.TextField()
    key_handle = models.TextField()
    public_key = models.TextField()
    transports = models.TextField(default='[]')
    counter = models.IntegerField(default=0)

    # django-otp api
    def generate_challenge(self):
        request = U2fDevice.begin_authentication(self.user, self.app_id)
        cache.set(request.challenge, request, U2F_REQUEST_TIMEOUT)
        return request.data_for_client

    def verify_token(self, token):
        '''
        Warning, the django-otp api does not allow associating challenges with
        a particular session. As a result anyone with the challenge is able to
        authenticate with this device.
        Because U2F is a hardware component this is an acceptable risk for most
        use cases. If you really care about this you should not use the
        django-otp api and authenticate to each specific device like django-otp
        recommends.
        '''
        response = SignResponse.wrap(json.loads(token))
        request = cache.get(response.clientData.challenge)
        if request is None:
            return False
        cache.delete(response.clientData.challenge)
        return U2fDevice.complete_authentication(self.user, request, response)
    # /django-otp api

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
            device, counter, _presence = complete_authentication(
                request, response)
        except ValueError:
            return False
        queryset = cls.objects.filter(
            user=user, key_handle=device['keyHandle'], confirmed=True)
        n = queryset.filter(counter__lt=counter).update(counter=counter)
        if n == 0:
            try:
                u2f_device = queryset.get()
            except cls.DoesNotExist:
                return False
            log.error(
                'U2F appears to be cloned, expected counter > %d but got %d '
                'instead.', u2f_device.counter, counter)
            return False
        elif n > 1:
            # This should never happen because all the users keys are included
            # in the registration and U2F does not allow registering the same
            # key twice.
            for u2f_device in queryset.order_by('id')[1:]:
                log.warning('Removing duplicate key %r', u2f_device)
                u2f_device.delete()
        return True

    def as_device_registration(self):
        return DeviceRegistration(
            appId=self.app_id, version=self.version, keyHandle=self.key_handle,
            publicKey=self.public_key, transports=json.loads(self.transports))
