from http import HTTPStatus
from re import match as re_match
from unittest import mock

from authlib.jose import jwt
from pytest import fixture

from .utils import headers, load_fixture


def implemented_routes():
    yield '/observe/observables'
    yield '/refer/observables'


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
def expected_payload(any_route, client, valid_json):
    app = client.application

    payload = None

    if any_route.startswith('/deliberate'):
        payload = {}

    if any_route.startswith('/observe'):
        sightings = load_fixture('sightings')
        indicators = load_fixture('indicators')
        relationships = load_fixture('relationships')

        class TransientID:
            uuid4 = '-'.join([
                '[a-f0-9]{8}',
                '[a-f0-9]{4}',
                '4[a-f0-9]{3}',
                '[89ab][a-f0-9]{3}',
                '[a-f0-9]{12}',
            ])

            def __init__(self, entity_type):
                self.pattern = f'^transient:{entity_type}-{self.uuid4}$'

            def __eq__(self, other):
                return bool(re_match(self.pattern, other))

        for sighting in sightings['docs']:
            sighting['id'] = TransientID('sighting')

        for indicator in indicators['docs']:
            indicator['id'] = TransientID('indicator')

        for relationship in relationships['docs']:
            relationship['id'] = TransientID('relationship')
            relationship['source_ref'] = TransientID('sighting')
            relationship['target_ref'] = TransientID('indicator')

        payload = {
            'sightings': sightings,
            'indicators': indicators,
            'relationships': relationships,
        }

    if any_route.startswith('/refer'):
        observable_types = app.config['GTI_OBSERVABLE_TYPES']

        def type_of(observable):
            return observable_types[observable['type']]

        url_template = app.config['GTI_UI_SEARCH_URL']

        payload = [
            {
                'id': 'ref-gti-search-{type}-{value}'.format(**observable),
                'title': f'Search for this {type_of(observable)}',
                'description': (
                    f'Lookup this {type_of(observable)} '
                    'on Gigamon ThreatINSIGHT'
                ),
                'url': url_template.format(query=observable['value']),
                'categories': ['Search', 'Gigamon ThreatINSIGHT'],
            }
            for observable in valid_json
            if observable['type'] in observable_types
        ]

    assert payload is not None, f'Unknown route: {any_route}.'

    return {'data': payload}


def test_enrich_call_success(any_route,
                             client,
                             valid_json,
                             valid_jwt,
                             expected_payload):
    app = client.application

    response = None

    if any_route.startswith('/deliberate'):
        response = client.post(any_route)

    if any_route.startswith('/observe'):
        target = 'api.enrich.get_events_for_observable'

        def side_effect(_, observable):
            data = (
                load_fixture('workflow/events_for_observable')
                if observable['type'] == 'sha256' else
                []
            )
            return data, None

        with mock.patch(target) as get_events_for_observable_mock:
            get_events_for_observable_mock.side_effect = side_effect

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
