from unittest import mock
from urllib.parse import urljoin
from uuid import uuid4

from pytest import fixture

from api.integration import (
    get_detections_for_entity,
    get_events_for_detection,
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


def test_get_detections_for_entity_failure(client, gti_api_request):
    app = client.application

    expected_error = {
        'code': 'code',
        'message': 'message',
    }

    gti_api_request.return_value = gti_api_response(
        ok=False,
        payload={'error': expected_error},
    )

    key = 'key'
    entity = 'entity'

    detections, error = get_detections_for_entity(key, entity)

    expected_method = 'GET'
    expected_url = urljoin(
        app.config['GTI_API_FAMILY_URLS']['detection'],
        'detections',
    )
    expected_headers = {
        'Authorization': f'IBToken {key}',
        'User-Agent': app.config['CTR_USER_AGENT'],
    }
    expected_params = {
        'indicator_value': entity,
        'status': 'active',
        'include': ['indicators', 'rules'],
    }

    gti_api_request.assert_called_once_with(
        expected_method,
        expected_url,
        headers=expected_headers,
        params=expected_params,
    )

    assert detections is None
    assert error == expected_error


def test_get_detections_for_entity_success(client, gti_api_request):
    app = client.application

    expected_rules = [{'uuid': str(uuid4())} for _ in range(5)]
    expected_detections = [
        {'uuid': str(uuid4()), 'rule_uuid': expected_rules[index % 5]['uuid']}
        for index in range(10)
    ]

    gti_api_request.return_value = gti_api_response(
        ok=True,
        payload={'detections': expected_detections, 'rules': expected_rules},
    )

    expected_detections = [
        {'uuid': detection['uuid'], 'rule': rule}
        for detection, rule in zip(expected_detections, expected_rules * 2)
    ]

    key = 'key'
    entity = 'entity'

    detections, error = get_detections_for_entity(key, entity)

    expected_method = 'GET'
    expected_url = urljoin(
        app.config['GTI_API_FAMILY_URLS']['detection'],
        'detections',
    )
    expected_headers = {
        'Authorization': f'IBToken {key}',
        'User-Agent': app.config['CTR_USER_AGENT'],
    }
    expected_params = {
        'indicator_value': entity,
        'status': 'active',
        'include': ['indicators', 'rules'],
    }

    gti_api_request.assert_called_once_with(
        expected_method,
        expected_url,
        headers=expected_headers,
        params=expected_params,
    )

    assert detections == expected_detections
    assert error is None


def test_get_events_for_detection_failure(client, gti_api_request):
    app = client.application

    expected_error = {
        'code': 'code',
        'message': 'message',
    }

    gti_api_request.return_value = gti_api_response(
        ok=False,
        payload={'error': expected_error},
    )

    key = 'key'
    detection_uuid = 'detection_uuid'

    events, error = get_events_for_detection(key, detection_uuid)

    expected_method = 'GET'
    expected_url = urljoin(
        app.config['GTI_API_FAMILY_URLS']['detection'],
        'events',
    )
    expected_headers = {
        'Authorization': f'IBToken {key}',
        'User-Agent': app.config['CTR_USER_AGENT'],
    }
    expected_params = {
        'detection_uuid': detection_uuid,
    }

    gti_api_request.assert_called_once_with(
        expected_method,
        expected_url,
        headers=expected_headers,
        params=expected_params,
    )

    assert events is None
    assert error == expected_error


def test_get_events_for_detection_success(client, gti_api_request):
    app = client.application

    expected_events = [{'event': {'uuid': str(uuid4())}} for _ in range(10)]

    gti_api_request.return_value = gti_api_response(
        ok=True,
        payload={'events': expected_events},
    )

    expected_events = [event['event'] for event in expected_events]

    key = 'key'
    detection_uuid = 'detection_uuid'

    events, error = get_events_for_detection(key, detection_uuid)

    expected_method = 'GET'
    expected_url = urljoin(
        app.config['GTI_API_FAMILY_URLS']['detection'],
        'events',
    )
    expected_headers = {
        'Authorization': f'IBToken {key}',
        'User-Agent': app.config['CTR_USER_AGENT'],
    }
    expected_params = {
        'detection_uuid': detection_uuid,
    }

    gti_api_request.assert_called_once_with(
        expected_method,
        expected_url,
        headers=expected_headers,
        params=expected_params,
    )

    assert events == expected_events
    assert error is None


def test_get_events_for_entity_failure(client, gti_api_request):
    app = client.application

    expected_error = {
        'code': 'code',
        'message': 'message',
    }

    gti_api_request.return_value = gti_api_response(
        ok=False,
        payload={'error': expected_error},
    )

    key = 'key'
    entity = 'entity'

    events, error = get_events_for_entity(key, entity)

    expected_method = 'POST'
    expected_url = urljoin(
        app.config['GTI_API_FAMILY_URLS']['event'],
        'query',
    )
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

    expected_events = [{'uuid': str(uuid4())} for _ in range(10)]

    gti_api_request.return_value = gti_api_response(
        ok=True,
        payload={'events': expected_events},
    )

    key = 'key'
    entity = 'entity'

    events, error = get_events_for_entity(key, entity)

    expected_method = 'POST'
    expected_url = urljoin(
        app.config['GTI_API_FAMILY_URLS']['event'],
        'query',
    )
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
