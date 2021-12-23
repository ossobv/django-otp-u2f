import pytest

from otp_u2f.utils import Webauthn


@pytest.fixture
def webauthn(settings):
    settings.OTP_U2F_RP_ID = 'localhost.osso.ninja'
    webauthn = Webauthn()
    assert webauthn.rp_id == 'localhost.osso.ninja'
    return webauthn
