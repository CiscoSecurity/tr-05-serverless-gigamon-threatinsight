from collections import defaultdict
from http import HTTPStatus
from ssl import SSLCertVerificationError
from urllib.parse import urljoin

import datetime
import requests
from flask import current_app
from requests.exceptions import SSLError


def _url(family, route):
    return urljoin(current_app.config['GTI_API_FAMILY_URLS'][family], route)


def _headers(key):
    return {
        'Authorization': f'IBToken {key}',
        'User-Agent': current_app.config['CTR_USER_AGENT'],
    }


def _request(method, url, **kwargs):
    key = kwargs.pop('key', None)

    if key is None:
        # Mimic the GTI API error response payload.
        error = {
            'code': 'client.invalid_authentication',
            'message': 'Authentication is invalid.',
        }
        return None, error

    kwargs['headers'] = _headers(key)

    try:
        response = requests.request(method, url, **kwargs)
    except SSLError as error:
        # Go through a few layers of wrapped exceptions.
        error = error.args[0].reason.args[0]
        # Assume that a certificate could not be verified.
        assert isinstance(error, SSLCertVerificationError)
        reason = getattr(error, 'verify_message', error.args[0]).capitalize()
        error = {
            'code': 'ssl certificate verification failed',
            'message': f'Unable to verify SSL certificate: {reason}.',
        }
        return None, error

    if response.ok:
        return response.json(), None

    else:
        error = response.json()['error']
        # The GTI API error response payload is already well formatted,
        # so just leave only the fields of interest and discard the rest.
        if response.status_code in (HTTPStatus.UNAUTHORIZED,
                                    HTTPStatus.FORBIDDEN):
            message = f'Authorization failed: {error["message"]}'
        else:
            message = error['message']

        error = {
            'code': error['code'],
            'message': message,
        }
        return None, error


def get_detections_for_entity(key, entity):
    url = _url('detection', 'detections')

    params = {
        'indicator_value': entity,
        'status': 'active',
        'include': ['indicators', 'rules'],
    }

    data, error = _request('GET', url, key=key, params=params)

    if error:
        return None, error

    detections = data['detections']

    for detection in detections:
        rule_uuid = detection.pop('rule_uuid')

        detection['rule'] = next(
            rule
            for rule in data['rules']
            if rule['uuid'] == rule_uuid
        )

    return detections, None


def get_events_for_detection(key, detection_uuid):
    url = _url('detection', 'events')

    params = {
        'detection_uuid': detection_uuid,
    }

    data, error = _request('GET', url, key=key, params=params)

    if error:
        return None, error

    events = [event['event'] for event in data['events']]

    return events, None


def mil_time(date):
    return str(date)[:-3]+'Z'


def get_events(key, observable, event_uuids):
    url = _url('event', 'query')

    limit = current_app.config['CTR_ENTITIES_LIMIT'] - len(event_uuids)
    events = []
    now = datetime.datetime.now()
    end_date = now.isoformat()
    start_date = (now - datetime.timedelta(days=1)).isoformat()
    day_range = current_app.config['DAY_RANGE']
    while day_range and len(events) < limit:
        json = {
            'query': f"{observable['type']} = '{observable['value']}'",
            'start_date': mil_time(start_date),
            'end_date': mil_time(end_date)
        }
        data, error = _request('POST', url, key=key, json=json)
        if error:
            return None, error
        end_date, start_date = start_date, (
            datetime.datetime.fromisoformat(start_date) -
            datetime.timedelta(days=1)
        ).isoformat()
        events.extend(event for event in data['events'] if
                      event['uuid'] not in event_uuids and is_allowed(
                          event['customer_id'])
                      )
        day_range -= 1

    return events, None


def get_dhcp_records_by_ip(key, event_time_by_ip):
    url = _url('entity', 'entity/tracking/bulk/get/ip')

    entities = [
        {'ip': ip, 'event_time': event_time}
        for ip, event_time in event_time_by_ip.items()
    ]

    if not entities:
        # Let's immediately return an empty dict here to simplify further
        # processing. Even if we make a real request to the GTI API instead,
        # it will fail with a message like 'No entities specified.' anyway.
        return {}, None

    json = {
        'entities': entities,
    }

    data, error = _request('POST', url, key=key, json=json)

    if error:
        return None, error

    dhcp_records = data['entity_tracking_bulk_response']['dhcp']

    dhcp_records_by_ip = defaultdict(list)

    for record in dhcp_records:
        dhcp_records_by_ip[record['ip']].append(record)

    return dhcp_records_by_ip, None


def is_allowed(account: str) -> bool:
    return (
        current_app.config['GTI_ALLOW_TEST_ACCOUNTS'] or
        account not in current_app.config['GTI_TEST_ACCOUNTS']
    )
