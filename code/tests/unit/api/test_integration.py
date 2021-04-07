from unittest import mock
from urllib.parse import urljoin
from uuid import uuid4

from pytest import fixture

from api.integration import (
    get_detections_for_entity,
    get_events_for_detection,
    get_events_for_entity,
    get_dhcp_records_by_ip,
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
    observable = app.config['GTI_TEST_ENTITY']

    events, error = get_events_for_entity(key, observable)

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
        'query': "ip = '8.8.8.8'",
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
    observable = app.config['GTI_TEST_ENTITY']

    events, error = get_events_for_entity(key, observable)

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
        'query': "ip = '8.8.8.8'",
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


def test_get_dhcp_records_by_ip_failure(client, gti_api_request):
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
    event_time_by_ip = {
        'ip_1': 'event_time_1',
        'ip_2': 'event_time_2',
        'ip_3': 'event_time_3',
    }

    dhcp_records_by_ip, error = get_dhcp_records_by_ip(key, event_time_by_ip)

    expected_method = 'POST'
    expected_url = urljoin(
        app.config['GTI_API_FAMILY_URLS']['entity'],
        'entity/tracking/bulk/get/ip',
    )
    expected_headers = {
        'Authorization': f'IBToken {key}',
        'User-Agent': app.config['CTR_USER_AGENT'],
    }
    expected_json = {
        'entities': [
            {'ip': 'ip_1', 'event_time': 'event_time_1'},
            {'ip': 'ip_2', 'event_time': 'event_time_2'},
            {'ip': 'ip_3', 'event_time': 'event_time_3'},
        ],
    }

    gti_api_request.assert_called_once_with(
        expected_method,
        expected_url,
        headers=expected_headers,
        json=expected_json,
    )

    assert dhcp_records_by_ip is None
    assert error == expected_error


def test_get_dhcp_records_by_ip_success(client, gti_api_request):
    app = client.application

    expected_dhcp_records = [
        {'ip': ip, 'account_code': account_code}
        for account_code in ['account_code_1', 'account_code_2']
        for ip in ['ip_1', 'ip_2', 'ip_3']
    ]

    gti_api_request.return_value = gti_api_response(
        ok=True,
        payload={
            'entity_tracking_bulk_response': {'dhcp': expected_dhcp_records},
        },
    )

    expected_dhcp_records_by_ip = {
        ip: [
            {'ip': ip, 'account_code': account_code}
            for account_code in ['account_code_1', 'account_code_2']
        ]
        for ip in ['ip_1', 'ip_2', 'ip_3']
    }

    key = 'key'
    event_time_by_ip = {
        'ip_1': 'event_time_1',
        'ip_2': 'event_time_2',
        'ip_3': 'event_time_3',
    }

    dhcp_records_by_ip, error = get_dhcp_records_by_ip(key, event_time_by_ip)

    expected_method = 'POST'
    expected_url = urljoin(
        app.config['GTI_API_FAMILY_URLS']['entity'],
        'entity/tracking/bulk/get/ip',
    )
    expected_headers = {
        'Authorization': f'IBToken {key}',
        'User-Agent': app.config['CTR_USER_AGENT'],
    }
    expected_json = {
        'entities': [
            {'ip': 'ip_1', 'event_time': 'event_time_1'},
            {'ip': 'ip_2', 'event_time': 'event_time_2'},
            {'ip': 'ip_3', 'event_time': 'event_time_3'},
        ],
    }

    gti_api_request.assert_called_once_with(
        expected_method,
        expected_url,
        headers=expected_headers,
        json=expected_json,
    )

    assert dhcp_records_by_ip == expected_dhcp_records_by_ip
    assert error is None
