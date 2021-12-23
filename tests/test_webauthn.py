from base64 import urlsafe_b64decode, urlsafe_b64encode

import pytest

from .factories import U2fDeviceFactory


def ub64_decode(s):
    if isinstance(s, str):
        s = s.encode()
    return urlsafe_b64decode(s + b'===')


def ub64_encode(s):
    return urlsafe_b64encode(s).decode()


@pytest.mark.django_db()
def test_webauthn_register_begin(webauthn):
    device = U2fDeviceFactory(
        version='U2F_V2',
        credential='xQ2Uq68EUbvH_6ITMGcABDdb9N0Pkmf-g8gaU2uOrB33MfvtJBfwf4YJBmml803DbJ_jOtm4omGsNJwo7iRMRg==',  # noqa
        public_key='BHKBOcZ38yDS9eJshaol7Uhbl_YIuLKLATusEtHfZdzTPGCJPaW5Tq1fgYrgi3ddCdUI53BgdzIUNQT__WSYd9I===')  # noqa

    request, state = webauthn.register_begin(device.user)
    key = request['publicKey']
    assert key['challenge'] == ub64_decode(state['challenge'])
    assert key['user']['id'] == str(device.user.pk).encode()
    assert key['user']['name'] == device.user.username
    assert len(key['excludeCredentials']) == 1
    cred = key['excludeCredentials'][0]
    assert ub64_encode(cred['id']) == device.credential
    assert cred['type'] == 'public-key'
    assert key['extensions'] == {
        'appidExclude': 'https://localhost.osso.ninja'}


def test_webauthn_register_complete(webauthn):
    credential_id = 'WwyEN7OnJb6KhQS_NDn4oGbiVPSuIxmKwo-77r_8nG2BKhoyQlYvuG3uS8Wa688Yi_tZNFG7mXhRaC3lUtWCnw=='  # noqa
    public_key = 'pQECAyYgASFYIGX54GU6pZBsdbVEw6B7sGCrtKUaHmu62JTMBLd_U64_IlggERQvKwWtfZX8mvREWzv1mrTh2tsLvHlcCCH4247nZpM='  # noqa
    state = {
        'challenge': 'Mjl7qc7IRNrjUgTssfOdCm0Uz4u_94de0b-feXDAp-U',
        'user_verification': 'discouraged',
    }
    response = webauthn.decode('om5jbGllbnREYXRhSlNPTliVeyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiTWpsN3FjN0lSTnJqVWdUc3NmT2RDbTBVejR1Xzk0ZGUwYi1mZVhEQXAtVSIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Lm9zc28ubmluamE6NTAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX1xYXR0ZXN0YXRpb25PYmplY3RY4qNjZm10ZG5vbmVnYXR0U3RtdKBoYXV0aERhdGFYxBJciu5tKwqax_aF3hn1zLS8_CqAzDW7sSirmsXnvXVRQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEBbDIQ3s6clvoqFBL80OfigZuJU9K4jGYrCj7vuv_ycbYEqGjJCVi-4be5LxZrrzxiL-1k0UbuZeFFoLeVS1YKfpQECAyYgASFYIGX54GU6pZBsdbVEw6B7sGCrtKUaHmu62JTMBLd_U64_IlggERQvKwWtfZX8mvREWzv1mrTh2tsLvHlcCCH4247nZpM=')  # noqa

    authenticator = webauthn.register_complete(state, response)
    credential = authenticator.credential_data
    assert authenticator.rp_id_hash.hex() == '125c8aee6d2b0a9ac7f685de19f5ccb4bcfc2a80cc35bbb128ab9ac5e7bd7551'  # noqa
    assert authenticator.counter == 0
    assert credential.aaguid.hex() == '00000000000000000000000000000000'
    assert ub64_encode(credential.credential_id) == credential_id
    assert webauthn.encode(credential.public_key) == public_key


@pytest.mark.django_db()
def test_webauthn_authenticate_begin(webauthn):
    device = U2fDeviceFactory(
        version='U2F_V2',
        credential='xQ2Uq68EUbvH_6ITMGcABDdb9N0Pkmf-g8gaU2uOrB33MfvtJBfwf4YJBmml803DbJ_jOtm4omGsNJwo7iRMRg==',  # noqa
        public_key='BHKBOcZ38yDS9eJshaol7Uhbl_YIuLKLATusEtHfZdzTPGCJPaW5Tq1fgYrgi3ddCdUI53BgdzIUNQT__WSYd9I===')  # noqa

    request, state = webauthn.authenticate_begin(device.user)
    key = request['publicKey']
    assert key['challenge'] == ub64_decode(state['challenge'])
    assert key['rpId'] == 'localhost.osso.ninja'
    assert key['userVerification'] == 'discouraged'
    assert key['extensions'] == {'appid': 'https://localhost.osso.ninja'}
    assert len(key['allowCredentials']) == 1
    cred = key['allowCredentials'][0]
    assert ub64_encode(cred['id']) == device.credential
    assert cred['type'] == 'public-key'


@pytest.mark.django_db()
def test_webauthn_authenticate_complete(webauthn):
    device = U2fDeviceFactory(
        credential='n8ZklynFZSmYNrICld-ShxDR64QVrov2FEmy-PaHVtVE_WCj1HpLfPMgdDBQEBK5tC7TY3U0iNGTDiWWfxLylg==',  # noqa
        public_key='pQECAyYgASFYIKL35NsyHSsIXBqC2upUvILPoOzkuAPc2x1AT7Mkvm0fIlggJVbR-teZTDVVL7NMRLob3gZmnz0hzloFXHzOukIWIF8=')  # noqa

    state = {
        'challenge': 'bnRQVde1p9L_W70ll7_HOxY3WMRME57IIVJURPr16Sk',
        'user_verification': None,
    }
    data = webauthn.decode('pGlzaWduYXR1cmVYSDBGAiEAjJz5c08jnc4kxvA1mCtd_oUfejhqbpKvp69q1CU6gqICIQDE8HZY1kwAaBOAm_WdhtLH0WUB-rd6FcDIEX477ddhQmxjcmVkZW50aWFsSWRYQJ_GZJcpxWUpmDayApXfkocQ0euEFa6L9hRJsvj2h1bVRP1go9R6S3zzIHQwUBASubQu02N1NIjRkw4lln8S8pZuY2xpZW50RGF0YUpTT05YknsidHlwZSI6IndlYmF1dGhuLmdldCIsImNoYWxsZW5nZSI6ImJuUlFWZGUxcDlMX1c3MGxsN19IT3hZM1dNUk1FNTdJSVZKVVJQcjE2U2siLCJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5vc3NvLm5pbmphOjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9cWF1dGhlbnRpY2F0b3JEYXRhWCUSXIrubSsKmsf2hd4Z9cy0vPwqgMw1u7Eoq5rF5711UQEAAAAE')  # noqa

    credential, authenticator = webauthn.authenticate_complete(
        state, data, device.user)
    assert credential.aaguid == device.aaguid.bytes
    assert ub64_encode(credential.credential_id) == device.credential  # noqa
    assert webauthn.encode(credential.public_key) == device.public_key
    assert authenticator.rp_id_hash.hex() == '125c8aee6d2b0a9ac7f685de19f5ccb4bcfc2a80cc35bbb128ab9ac5e7bd7551'  # noqa
    assert authenticator.counter == 4
