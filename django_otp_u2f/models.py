import json

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import NameOID
from django.conf import settings
from django.db import models
from django_otp.models import Device

from u2flib_server.model import DeviceRegistration
from u2flib_server.u2f import (begin_registration, begin_authentication,
                               complete_registration, complete_authentication)
from u2flib_server.utils import websafe_decode


class U2FDevice(Device):
    @staticmethod
    def begin_registration():
        """
        Start registering a U2F security key.

        Keep enroll_challenge safe server-side, and give data_for_client to the client. When you get the data back from
        the client, call U2FDevice.create_key with it.

        :return: enroll_challenge, data_for_client
        """
        enroll = begin_registration(settings.OTP_U2F_APP_ID, [])
        return enroll.json, enroll.data_for_client

    def create_key(self, enroll_challenge, data):
        u2f_key = U2FKey.create(self, enroll_challenge, data)
        self.confirmed = True
        return u2f_key

    def generate_challenge(self):
        challenge = begin_authentication(settings.OTP_U2F_APP_ID,
                                         [key.as_device_registration() for key in self.u2fkey_set.all()])
        U2FChallenge.objects.create(device=self,
                                    challenge=challenge.data_for_client['challenge'],
                                    challenge_data=challenge.json)
        return challenge.data_for_client

    def verify_token(self, token):
        client_data = json.loads(websafe_decode(token['clientData']).decode())
        try:
            u2f_challenge = U2FChallenge.objects.get(challenge=client_data['challenge'], device=self)
        except U2FChallenge.DoesNotExist:
            return False
        try:
            complete_authentication(u2f_challenge.challenge_data, token, [settings.OTP_U2F_APP_ID])
        except ValueError:
            return False
        u2f_challenge.delete()
        return True

    def save(self, *args, **kwargs):
        self.confirmed = self.u2fkey_set.exists() if self.pk else False
        super(U2FDevice, self).save(*args, **kwargs)


class U2FKey(models.Model):
    device = models.ForeignKey(U2FDevice, on_delete=models.CASCADE)
    name = models.TextField()
    version = models.CharField(max_length=16, blank=True)
    public_key = models.TextField(blank=True)
    transports = models.TextField(default='[]', blank=True)
    enroll_challenge = models.TextField(blank=True)
    key_handle = models.TextField(blank=True)

    def as_device_registration(self):
        return DeviceRegistration(version=self.version,
                                  keyHandle=self.key_handle,
                                  appId=settings.OTP_U2F_APP_ID,
                                  publicKey=self.public_key,
                                  transports=json.loads(self.transports))

    @classmethod
    def create(cls, u2f_device, enroll_challenge, data, name=None):
        data['version'] = 'U2F_V2'
        device, cert = complete_registration(json.loads(enroll_challenge), data, [settings.OTP_U2F_APP_ID])
        if not name:
            cert = x509.load_der_x509_certificate(cert, default_backend())
            name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        return cls.objects.create(name=name,
                                  device=u2f_device,
                                  version=device['version'],
                                  public_key=device['publicKey'],
                                  transports=json.dumps(device['transports']),
                                  key_handle=device['keyHandle'])

    def delete(self, *args, **kwargs):
        super(U2FKey, self).delete(*args, **kwargs)
        self.device.save()


class U2FChallenge(models.Model):
    device = models.ForeignKey(U2FDevice)
    challenge = models.TextField(db_index=True)
    challenge_data = models.TextField()

    created = models.DateTimeField(auto_now_add=True)
