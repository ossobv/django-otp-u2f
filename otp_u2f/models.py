from base64 import urlsafe_b64decode, urlsafe_b64encode
import logging

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import SuspiciousOperation
from django.db.models import (
    CharField, F, PositiveIntegerField, TextField, UUIDField)
from django.utils import timezone
from django.utils.functional import cached_property

from django_otp.models import Device, ThrottlingMixin

from fido2 import cbor
from fido2.ctap2 import AttestedCredentialData

log = logging.getLogger(__name__)


U2F_REQUEST_TIMEOUT = 300


class DeviceClonedError(SuspiciousOperation):
    pass


class U2fDevice(ThrottlingMixin, Device):
    rp_id = CharField(max_length=100)
    version = CharField(max_length=16)
    aaguid = UUIDField()
    credential = TextField()
    public_key = TextField()
    counter = PositiveIntegerField(default=0)

    # django-otp api
    def generate_challenge(self):
        from .utils import Webauthn
        webauthn = Webauthn()
        request, state = webauthn.authenticate_begin(self.user)
        cache.set(state['challenge'], state, U2F_REQUEST_TIMEOUT)
        return request

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
            response = self.webauthn.decode(token)
        except (TypeError, ValueError):
            return False

        try:
            state = cache.get(response['clientData']['challenge'])
            if state is None:
                return False
            cache.delete(response['clientData']['challenge'])
            if self.credential != urlsafe_b64encode(
                    response['credentialId']).decode():
                # Using a different device.
                return False
        except KeyError:
            return False

        return self.verify_webauthn(state, response)
    # /django-otp api

    @cached_property
    def webauthn(self):
        from .utils import Webauthn
        return Webauthn()

    def verify_webauthn(self, state, response):
        try:
            credential, authenticator = self.webauthn.authenticate_complete(
                state, response, self.user)
        except ValueError:
            self.increment_failure_counter()
            return False

        try:
            self.update_usage_counter(authenticator.counter)
        except DeviceClonedError:
            return False
        return True

    def get_throttle_factor(self):
        return getattr(settings, 'OTP_U2F_THROTTLE_FACTOR', 1)

    @classmethod
    def get_credentials(cls, user):
        return [
            key.as_credential()
            for key in cls.objects.filter(user=user, confirmed=True)]

    @classmethod
    def get_device(cls, user, credential):
        return cls.objects.get(
            user=user, confirmed=True,
            credential=urlsafe_b64encode(credential).decode())

    def increment_failure_counter(self):
        U2fDevice.objects.filter(pk=self.pk).update(
            throttling_failure_timestamp=timezone.now(),
            throttling_failure_count=F('throttling_failure_count') + 1
        )
        self.refresh_from_db()

    def update_usage_counter(self, counter):
        queryset = U2fDevice.objects.filter(pk=self.pk)
        n = queryset.filter(counter__lt=counter).update(
            throttling_failure_timestamp=None, throttling_failure_count=0,
            counter=counter)
        if n == 0:
            queryset.update(
                confirmed=False,
                throttling_failure_timestamp=timezone.now(),
                throttling_failure_count=F('throttling_failure_count') + 1,
            )
            self.refresh_from_db()
            raise DeviceClonedError(
                'Device appears to be cloned, expected counter > {} but got '
                '{} instead. The device {} has been disabled.'.format(
                    self.counter, counter, self.persistent_id))
        self.refresh_from_db()

    def as_credential(self):
        credential = urlsafe_b64decode(self.credential)
        public_key = urlsafe_b64decode(self.public_key)
        if self.version == 'U2F_V2':
            return AttestedCredentialData.from_ctap1(credential, public_key)
        else:
            return AttestedCredentialData.create(
                self.aaguid.bytes, credential, cbor.decode(public_key))
