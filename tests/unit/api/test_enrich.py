from http import HTTPStatus
from unittest import mock

from authlib.jose import jwt
from pytest import fixture

from .utils import headers


def implemented_routes():
    yield '/observe/observables'


@fixture(scope='module',
         params=implemented_routes(),
         ids=lambda route: f'POST {route}')
def implemented_route(request):
    return request.param


@fixture(scope='module')
def invalid_json():
    return [{'type': 'unknown', 'value': ''}]


def test_enrich_call_with_invalid_json_failure(implemented_route,
                                               client,
                                               invalid_json):
    response = client.post(implemented_route, json=invalid_json)

    # The actual error message is quite unwieldy, so let's just ignore it.
    expected_payload = {
        'errors': [
            {
                'code': 'invalid payload received',
                'message': mock.ANY,
                'type': 'fatal',
            }
        ]
    }

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


def gti_api_routes():
    yield '/observe/observables'


@fixture(scope='module',
         params=gti_api_routes(),
         ids=lambda route: f'POST {route}')
def gti_api_route(request):
    return request.param


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
        {
            'type': 'email',
            'value': 'admin@cisco.com',
        },
    ]


def test_enrich_call_with_valid_json_but_invalid_jwt_failure(gti_api_route,
                                                             client,
                                                             valid_json,
                                                             invalid_jwt):
    response = client.post(gti_api_route,
                           json=valid_json,
                           headers=headers(invalid_jwt))

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


def all_routes():
    yield '/deliberate/observables'
    yield '/observe/observables'
    yield '/refer/observables'


@fixture(scope='module',
         params=all_routes(),
         ids=lambda route: f'POST {route}')
def any_route(request):
    return request.param


@fixture(scope='module')
def gti_events():  # TODO
    return []


@fixture(scope='module')
def expected_payload(any_route, client):
    payload = None

    if any_route.startswith('/deliberate'):
        payload = {}

    if any_route.startswith('/observe'):  # TODO
        payload = {}

    if any_route.startswith('/refer'):
        payload = []

    assert payload is not None, f'Unknown route: {any_route}.'

    return {'data': payload}


def test_enrich_call_success(any_route,
                             client,
                             gti_events,
                             valid_json,
                             valid_jwt,
                             expected_payload):
    app = client.application

    response = None

    if any_route.startswith('/deliberate'):
        response = client.post(any_route)

    if any_route.startswith('/observe'):  # TODO
        target = 'api.enrich.get_events_for_observable'

        with mock.patch(target) as get_events_for_observable_mock:
            get_events_for_observable_mock.return_value = (gti_events, None)

            response = client.post(any_route,
                                   json=valid_json,
                                   headers=headers(valid_jwt))

            key = jwt.decode(valid_jwt, app.config['SECRET_KEY'])['key']

            get_events_for_observable_mock.assert_has_calls([
                mock.call(key, observable)
                for observable in valid_json
                if observable['type'] in app.config['GTI_OBSERVABLE_TYPES']
            ])

    if any_route.startswith('/refer'):
        response = client.post(any_route, json=valid_json)

    assert response is not None, f'Unknown route: {any_route}.'

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


def test_enrich_call_with_auth_error_from_gti_failure(gti_api_route,
                                                      client,
                                                      valid_json,
                                                      valid_jwt):
    app = client.application

    target = 'api.enrich.get_events_for_observable'
    error = {
        'code': 'client.invalid_authentication',
        'message': 'Authentication is invalid.',
    }

    with mock.patch(target) as get_events_for_observable_mock:
        get_events_for_observable_mock.return_value = (None, error)

        response = client.post(gti_api_route,
                               json=valid_json,
                               headers=headers(valid_jwt))

        key = jwt.decode(valid_jwt, app.config['SECRET_KEY'])['key']
        observable = next(
            observable
            for observable in valid_json
            if observable['type'] in app.config['GTI_OBSERVABLE_TYPES']
        )

        get_events_for_observable_mock.assert_called_once_with(key, observable)

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