from http import HTTPStatus
from unittest import mock

from pytest import fixture

from tests.unit.conftest import GTI_KEY
from tests.unit.api.mock_keys_for_tests import \
    EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
from .utils import headers


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


def test_health_call_success(route,
                             client,
                             valid_jwt,
                             rsa_api_request,
                             rsa_api_response):
    app = client.application

    rsa_api_request.return_value = rsa_api_response(
        EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
    )

    target = 'api.health.get_events'

    # Nothing really matters...
    data = ...

    with mock.patch(target) as get_events_mock:
        get_events_mock.return_value = (data, None)

        response = client.post(route, headers=headers(valid_jwt()))

        key = GTI_KEY
        entity = app.config['GTI_TEST_ENTITY']

        get_events_mock.assert_called_with(key, entity)

    expected_payload = {'data': {'status': 'ok'}}

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


def test_health_call_with_auth_error_from_gti_failure(route,
                                                      client,
                                                      valid_jwt,
                                                      rsa_api_request,
                                                      rsa_api_response):
    app = client.application

    rsa_api_request.return_value = rsa_api_response(
        EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
    )

    target = 'api.health.get_events'

    error = {
        'code': 'client.invalid_authentication',
        'message': 'Authentication is invalid.',
    }

    with mock.patch(target) as get_events_mock:
        get_events_mock.return_value = (None, error)

        response = client.post(route, headers=headers(valid_jwt()))

        key = GTI_KEY
        entity = app.config['GTI_TEST_ENTITY']

        get_events_mock.assert_called_with(key, entity)

    expected_payload = {
        'errors': [
            {
                'code': 'client : invalid authentication',
                'message': 'Authentication is invalid.',
                'type': 'fatal',
            }
        ]
    }

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload
