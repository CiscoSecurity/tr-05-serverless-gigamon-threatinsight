from unittest import mock

import jwt
from pytest import fixture

from app import app
from tests.unit.api.mock_keys_for_tests import PRIVATE_KEY

GTI_KEY = 'In Gigamon ThreatINSIGHT we trust!'


@fixture(scope='session')
def client():
    app.rsa_private_key = PRIVATE_KEY

    app.config['GTI_ALLOW_TEST_ACCOUNTS'] = 1

    app.testing = True

    with app.test_client() as client:
        yield client


@fixture(scope='function')
def rsa_api_request():
    with mock.patch('requests.get') as mock_request:
        yield mock_request


@fixture(scope='function')
def rsa_api_response():
    def _make_mock(payload):
        mock_response = mock.MagicMock()
        mock_response.json = lambda: payload
        return mock_response

    return _make_mock


@fixture(scope='session')
def valid_jwt(client):
    def _make_jwt(
            key=GTI_KEY,
            jwks_host='visibility.amp.cisco.com',
            aud='http://localhost',
            limit=100,
            kid='02B1174234C29F8EFB69911438F597FF3FFEE6B7',
            wrong_structure=False
    ):
        payload = {
            'key': key,
            'jwks_host': jwks_host,
            'aud': aud,
            'CTR_ENTITIES_LIMIT': limit
        }

        if wrong_structure:
            payload.pop('key')

        return jwt.encode(
            payload, client.application.rsa_private_key, algorithm='RS256',
            headers={
                'kid': kid
            }
        )

    return _make_jwt


@fixture(scope='module')
def valid_json():
    return [
        {
            'type': 'user',
            'value': 'admin',
        },
        {
            'type': 'ip',
            'value': '45.77.51.101',
        },
        {
            'type': 'domain',
            'value': 'securecorp.club'
        },
        {
            'type': 'md5',
            'value': '3319b1a422c785c221050f1152ad77cb',
        },
        {
            'type': 'sha1',
            'value': '2d7177f8466d82e28150572584928278ba72d435',
        },
        {
            'type': 'sha256',
            'value': (
                '9ffc7e4333d3be11b244d5f83b02ebcd194a671539f7faf1b5597d9209cc25c3'  # noqa: E501
            ),
        },
    ]
