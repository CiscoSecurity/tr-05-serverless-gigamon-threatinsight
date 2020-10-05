import json
from typing import Optional

from authlib.jose import jwt
from authlib.jose.errors import BadSignatureError, DecodeError
from flask import request, current_app, jsonify

from api.errors import AuthenticationRequiredError


def get_auth_token():
    expected_errors = {
        KeyError: 'Authorization header is missing',
        ValueError: 'JWT is missing',
        AssertionError: 'Wrong authorization type'
    }

    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return token
    except tuple(expected_errors) as error:
        raise AuthenticationRequiredError(expected_errors[error.__class__])


def get_key() -> Optional[str]:
    expected_errors = {
        KeyError: 'Wrong JWT payload structure',
        TypeError: '<SECRET_KEY> is missing',
        BadSignatureError: 'Failed to decode JWT with provided key',
        DecodeError: 'Wrong JWT structure'
    }
    token = get_auth_token()
    try:
        return jwt.decode(token, current_app.config['SECRET_KEY'])["key"]
    except tuple(expected_errors) as error:
        raise AuthenticationRequiredError(expected_errors[error.__class__])


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


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(error, data=None):
    error['code'] = error['code'].replace('.', ' : ').replace('_', ' ')

    # According to the official documentation, an error here means that the
    # corresponding TR module is in an incorrect state and needs to be
    # reconfigured, or the third-party service is down (for example, the API
    # being queried has temporary issues) and thus unresponsive:
    # https://visibility.amp.cisco.com/help/alerts-errors-warnings.
    error['type'] = 'fatal'

    payload = {'errors': [error]}
    if data:
        payload['data'] = data

    current_app.logger.error(payload)

    return jsonify(payload)
