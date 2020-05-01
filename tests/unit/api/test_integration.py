from unittest import mock
from urllib.parse import urljoin
from uuid import uuid4

from pytest import fixture

from api.integration import (
    get_events_for_entity,
)


@fixture(scope='function')
def gti_api_request():
    with mock.patch('requests.request') as mock_request:
        yield mock_request


def gti_api_response(*, ok, payload):
    mock_response = mock.MagicMock()

    mock_response.ok = ok

    mock_response.json = lambda: payload

    return mock_response


def test_get_events_for_entity_failure(client, gti_api_request):
    app = client.application

    expected_error = {
        'code': 'client.invalid_request',
        'message': 'query is required',
    }

    gti_api_request.return_value = gti_api_response(
        ok=False,
        payload={'error': expected_error},
    )

    key = 'key'
    entity = ''

    events, error = get_events_for_entity(key, entity)

    expected_method = 'POST'
    expected_url = urljoin(app.config['GTI_API_FAMILY_URLS']['event'], 'query')
    expected_headers = {
        'Authorization': f'IBToken {key}',
        'User-Agent': app.config['CTR_USER_AGENT'],
    }
    expected_json = {
        'query': entity,
        'limit': app.config['CTR_ENTITIES_LIMIT'],
    }

    gti_api_request.assert_called_once_with(
        expected_method,
        expected_url,
        headers=expected_headers,
        json=expected_json,
    )

    assert events is None
    assert error == expected_error


def test_get_events_for_entity_success(client, gti_api_request):
    app = client.application

    expected_events = [
        {'uuid': str(uuid4()), '...': ...}
        for _ in range(app.config['CTR_ENTITIES_LIMIT'])
    ]

    gti_api_request.return_value = gti_api_response(
        ok=True,
        payload={'events': expected_events},
    )

    key = 'key'
    entity = 'entity'

    events, error = get_events_for_entity(key, entity)

    expected_method = 'POST'
    expected_url = urljoin(app.config['GTI_API_FAMILY_URLS']['event'], 'query')
    expected_headers = {
        'Authorization': f'IBToken {key}',
        'User-Agent': app.config['CTR_USER_AGENT'],
    }
    expected_json = {
        'query': entity,
        'limit': app.config['CTR_ENTITIES_LIMIT'],
    }

    gti_api_request.assert_called_once_with(
        expected_method,
        expected_url,
        headers=expected_headers,
        json=expected_json,
    )

    assert events == expected_events
    assert error is None
