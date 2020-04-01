import json
from typing import Optional

import requests
from authlib.jose import jwt
from authlib.jose.errors import JoseError
from flask import request, current_app, jsonify


def get_jwt():
    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return jwt.decode(token, current_app.config['SECRET_KEY'])
    except (KeyError, ValueError, AssertionError, JoseError):
        return {}


def get_key() -> Optional[str]:
    return get_jwt().get('key')  # GTI_API_KEY


def get_json(schema):
    data = request.get_json(force=True, silent=True, cache=False)

    error = schema.validate(data) or None
    if error:
        data = None
        error = {
            'code': 'invalid payload received',
            'message': f'Invalid JSON payload received. {json.dumps(error)}.',
        }

    return data, error


def call_gti_api(key, method, url, **kwargs):
    if key is None:
        # Mimic the GTI API error response payload.
        error = {
            'code': 'client.invalid_authentication',
            'message': 'Authentication is invalid.',
        }
        return None, error

    headers = {
        'Authorization': f'IBToken {key}',
        'User-Agent': current_app.config['GTI_USER_AGENT'],
    }

    kwargs.setdefault('headers', {}).update(headers)

    response = requests.request(method, url, **kwargs)

    if response.ok:
        return response.json(), None

    else:
        error = response.json()['error']
        # The GTI API error response payload is already well formatted,
        # so just leave only the fields of interest and discard the rest.
        error = {
            'code': error['code'],
            'message': error['message'],
        }
        return None, error


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(error):
    error['code'] = error['code'].replace('.', ' : ').replace('_', ' ')

    # According to the official documentation, an error here means that the
    # corresponding TR module is in an incorrect state and needs to be
    # reconfigured, or the third-party service is down (for example, the API
    # being queried has temporary issues) and thus unresponsive:
    # https://visibility.amp.cisco.com/help/alerts-errors-warnings.
    error['type'] = 'fatal'

    return jsonify({'errors': [error]})
