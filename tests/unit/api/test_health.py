from http import HTTPStatus
from unittest import mock
from urllib.parse import quote

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


@fixture(scope='function')
def gti_api_request():
    with mock.patch('requests.request') as mock_request:
        yield mock_request


def gti_api_response(*, ok):
    mock_response = mock.MagicMock()

    mock_response.ok = ok

    if ok:
        payload = ...

    else:
        payload = {
            'error': {
                'code': 'client.invalid_authentication',
                'message': 'Authentication is invalid.',
                'ellipsis': ...,
            }
        }

    mock_response.json = lambda: payload

    return mock_response


def test_health_call_success(route, client, gti_api_request, valid_jwt):
    app = client.application

    gti_api_request.return_value = gti_api_response(ok=True)

    response = client.post(route, headers=headers(valid_jwt))

    expected_url = app.config['GTI_API_URLS']['entity']['summary'].format(
        entity=quote(app.config['GTI_TEST_ENTITY'], safe='')
    )

    expected_headers = {
        'Authorization': 'IBToken {[key]}'.format(
            jwt.decode(valid_jwt, app.config['SECRET_KEY'])
        ),
        'User-Agent': app.config['GTI_USER_AGENT'],
    }

    gti_api_request.assert_called_once_with('GET',
                                            expected_url,
                                            headers=expected_headers)

    expected_payload = {'data': {'status': 'ok'}}

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


def test_health_call_with_auth_error_from_gti_failure(route,
                                                      client,
                                                      gti_api_request,
                                                      valid_jwt):
    app = client.application

    gti_api_request.return_value = gti_api_response(ok=False)

    response = client.post(route, headers=headers(valid_jwt))

    expected_url = app.config['GTI_API_URLS']['entity']['summary'].format(
        entity=quote(app.config['GTI_TEST_ENTITY'], safe='')
    )

    expected_headers = {
        'Authorization': 'IBToken {[key]}'.format(
            jwt.decode(valid_jwt, app.config['SECRET_KEY'])
        ),
        'User-Agent': app.config['GTI_USER_AGENT'],
    }

    gti_api_request.assert_called_once_with('GET',
                                            expected_url,
                                            headers=expected_headers)

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
