from http import HTTPStatus
from pytest import fixture


def routes():
    yield '/watchdog'


@fixture(scope='module', params=routes(), ids=lambda route: f'GET {route}')
def route(request):
    return request.param


@fixture(scope='module')
def expected_payload(client):
    return {'data': 'test'}


def test_watchdog_call_success(route, client, expected_payload):
    response = client.get(route, headers={'Health-Check': 'test'})

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


def test_watchdog_call_failure(route, client):
    response = client.get(route)
    expected_payload = {
        'errors': [
            {
                'code': 'health check failed',
                'message': 'Invalid Health Check.',
                'type': 'fatal'
            }
        ]
    }

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload
