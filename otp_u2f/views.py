from django.http import HttpResponse
from django.views import View

from kleides_mfa.views.mixins import (
    SetupOrMFARequiredMixin, UnverifiedUserMixin)

from .forms import U2F_AUTHENTICATION_KEY, U2F_REGISTRATION_KEY
from .utils import Webauthn


class AuthenticateChallengeView(UnverifiedUserMixin, View):
    def post(self, request):
        webauthn = Webauthn(self.request)
        authenticate, state = webauthn.authenticate_begin(self.unverified_user)
        self.request.session[U2F_AUTHENTICATION_KEY] = state
        return HttpResponse(
            webauthn.encode(authenticate).rstrip('='),
            content_type='text/plain')


class RegisterChallengeView(SetupOrMFARequiredMixin, View):
    def post(self, request):
        webauthn = Webauthn(request)
        registration, state = webauthn.register_begin(request.user)
        self.request.session[U2F_REGISTRATION_KEY] = state
        return HttpResponse(
            webauthn.encode(registration).rstrip('='),
            content_type='text/plain')
