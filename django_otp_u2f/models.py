import json

import copy
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from django.conf import settings
from django.db import models
from django_otp.models import Device

from u2flib_server import u2f
from u2flib_server.model import DeviceRegistration
from u2flib_server.u2f import (begin_registration, begin_authentication,
                               complete_registration, complete_authentication)
from u2flib_server.utils import websafe_decode


class U2FDevice(Device):
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
    def enroll(cls, user):
        enroll = begin_registration(settings.OTP_U2F_APP_ID, [])
        device = cls.objects.create(user=user, confirmed=False, enroll_challenge=json.dumps(enroll.json))
        data_for_client = copy.deepcopy(enroll.data_for_client)
        return device, data_for_client

    def bind(self, data):
        data['version'] = 'U2F_V2'
        device, cert = complete_registration(json.loads(self.enroll_challenge), data, [settings.OTP_U2F_APP_ID])
        print(device, cert)
        self.version = device['version']
        self.public_key = device['publicKey']
        self.transports = json.dumps(device['transports'])
        self.key_handle = device['keyHandle']

        cert = x509.load_der_x509_certificate(cert, default_backend())
        # log.debug("Attestation certificate:\n%s",
        #           cert.public_bytes(Encoding.PEM))
        self.enroll_challenge = ''
        self.save()

    def generate_challenge(self):
        challenge = begin_authentication(settings.OTP_U2F_APP_ID,
                                         [self.as_device_registration()])
        u2f_challenge = U2FChallenge.objects.create(device=self,
                                                    challenge=challenge.data_for_client['challenge'],
                                                    challenge_data=challenge.json)
        data_for_client = copy.copy(challenge.data_for_client)
        return {
            'version': data_for_client['registeredKeys'][0]['version'],
            'challenge': data_for_client['challenge'],
            'appId': data_for_client['registeredKeys'][0]['appId'],
            'keyHandle': data_for_client['registeredKeys'][0]['keyHandle'],
            'requestId': u2f_challenge.id,
        }

    def verify_token(self, token):
        client_data = json.loads(websafe_decode(token['clientData']))
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


class U2FChallenge(models.Model):
    device = models.ForeignKey(U2FDevice)
    challenge = models.TextField(db_index=True)
    challenge_data = models.TextField()
