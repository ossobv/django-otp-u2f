import json
import logging

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import NameOID
from django.db import models
from django_otp.models import Device

from u2flib_server.model import DeviceRegistration
from u2flib_server.u2f import (begin_registration, begin_authentication,
                               complete_registration, complete_authentication)

log = logging.getLogger(__name__)


class U2FDevice(Device):
    app_id = models.CharField(max_length=100)
    version = models.CharField(max_length=16)
    key_handle = models.TextField()
    public_key = models.TextField()
    transports = models.TextField(default='[]')
    counter = models.IntegerField(default=0)

    @classmethod
    def begin_registration(cls, user, app_id):
        """
        Start registering a U2F security key.

        :return: request, data_for_client
        """
        request = begin_registration(
            app_id, [key.as_device_registration()
                     for key in cls.objects.filter(user=user, confirmed=True)])
        return request.json, request.data_for_client

    @classmethod
    def complete_registration(cls, user, request, response, name=None):
        response['version'] = 'U2F_V2'
        device, cert = complete_registration(request, response)
        if not name:
            cert = x509.load_der_x509_certificate(cert, default_backend())
            name = cert.subject.get_attributes_for_oid(
                    NameOID.COMMON_NAME)[0].value

        return cls.objects.create(
            user=user, name=name, confirmed=True, app_id=device['appId'],
            version=device['version'], key_handle=device['keyHandle'],
            public_key=device['publicKey'],
            transports=json.dumps(device['transports']))

    @classmethod
    def begin_authentication(cls, user, app_id):
        request = begin_authentication(
            app_id, [key.as_device_registration()
                     for key in cls.objects.filter(user=user, confirmed=True)])
        return request.json, request.data_for_client

    @classmethod
    def complete_authentication(cls, user, request, response):
        try:
            device, counter, _presence = complete_authentication(
                request, response)
        except ValueError:
            return False
        n = cls.objects.filter(
            user=user, key_handle=device['keyHandle'], counter__lt=counter,
            ).update(counter=counter)
        if n == 0:
            try:
                u2f_device = cls.objects.get(
                   user=user, key_handle=device['keyHandle'])
            except U2FDevice.DoesNotExist:
                return False
            log.error(
                'U2F appears to be cloned, expected counter > %d but got %d '
                'instead.', u2f_device.counter, counter)
            return False
        elif n > 1:
            for u2f_device in cls.objects.filter(
                    user=user, key_handle=device['keyHandle']
                    ).order_by('id')[1:]:
                log.warning('Removing duplicate key %r', u2f_device)
        return True

    def as_device_registration(self):
        return DeviceRegistration(
            appId=self.app_id, version=self.version, keyHandle=self.key_handle,
            publicKey=self.public_key, transports=json.loads(self.transports))
