from http import HTTPStatus
from unittest import mock

from authlib.jose import jwt
from pytest import fixture

from .utils import headers


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


def test_health_call_with_invalid_jwt_failure(route,
                                              client,
                                              invalid_jwt):
    response = client.post(route, headers=headers(invalid_jwt))

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


def test_health_call_success(route, client, valid_jwt):
    app = client.application

    target = 'api.health.get_events_for_entity'

    # Nothing really matters...
    data = ...

    with mock.patch(target) as get_events_for_entity_mock:
        get_events_for_entity_mock.return_value = (data, None)

        response = client.post(route, headers=headers(valid_jwt))

        key = jwt.decode(valid_jwt, app.config['SECRET_KEY'])['key']
        entity = app.config['GTI_TEST_ENTITY']

        get_events_for_entity_mock.assert_called_with(key, entity)

    expected_payload = {'data': {'status': 'ok'}}

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


def test_health_call_with_auth_error_from_gti_failure(route,
                                                      client,
                                                      valid_jwt):
    app = client.application

    target = 'api.health.get_events_for_entity'

    error = {
        'code': 'client.invalid_authentication',
        'message': 'Authentication is invalid.',
    }

    with mock.patch(target) as get_events_for_entity_mock:
        get_events_for_entity_mock.return_value = (None, error)

        response = client.post(route, headers=headers(valid_jwt))

        key = jwt.decode(valid_jwt, app.config['SECRET_KEY'])['key']
        entity = app.config['GTI_TEST_ENTITY']

        get_events_for_entity_mock.assert_called_with(key, entity)

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
