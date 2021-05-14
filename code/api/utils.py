import json
from json.decoder import JSONDecodeError
import jwt
import requests
from jwt import InvalidSignatureError, InvalidAudienceError, DecodeError
from requests.exceptions import ConnectionError, InvalidURL
from flask import request, current_app, jsonify

from api.errors import AuthenticationRequiredError

NO_AUTH_HEADER = 'Authorization header is missing'
WRONG_AUTH_TYPE = 'Wrong authorization type'
WRONG_PAYLOAD_STRUCTURE = 'Wrong JWT payload structure'
WRONG_JWT_STRUCTURE = 'Wrong JWT structure'
WRONG_AUDIENCE = 'Wrong configuration-token-audience'
KID_NOT_FOUND = 'kid from JWT header not found in API response'
WRONG_KEY = ('Failed to decode JWT with provided key. '
             'Make sure domain in custom_jwks_host '
             'corresponds to your SecureX instance region.')
JWK_HOST_MISSING = ('jwk_host is missing in JWT payload. Make sure '
                    'custom_jwks_host field is present in module_type')
WRONG_JWKS_HOST = ('Wrong jwks_host in JWT payload. Make sure domain follows '
                   'the visibility.<region>.cisco.com structure')


def set_ctr_entities_limit(payload):
    try:
        ctr_entities_limit = int(payload['CTR_ENTITIES_LIMIT'])
        assert ctr_entities_limit > 0

        if ctr_entities_limit > current_app.config['CTR_ENTITIES_LIMIT_MAX']:
            ctr_entities_limit = current_app.config['CTR_ENTITIES_LIMIT_MAX']

    except (KeyError, ValueError, AssertionError):
        ctr_entities_limit = current_app.config['CTR_ENTITIES_LIMIT_DEFAULT']

    current_app.config['CTR_ENTITIES_LIMIT'] = ctr_entities_limit


def get_auth_token():
    expected_errors = {
        KeyError: NO_AUTH_HEADER,
        AssertionError: WRONG_AUTH_TYPE
    }

    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return token
    except tuple(expected_errors) as error:
        raise AuthenticationRequiredError(expected_errors[error.__class__])


def get_public_key(jwks_host, token):
    expected_errors = {
        ConnectionError: WRONG_JWKS_HOST,
        InvalidURL: WRONG_JWKS_HOST,
        JSONDecodeError: WRONG_JWKS_HOST,
    }
    try:
        response = requests.get(f"https://{jwks_host}/.well-known/jwks")
        jwks = response.json()

        public_keys = {}
        for jwk in jwks['keys']:
            kid = jwk['kid']
            public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(
                json.dumps(jwk)
            )
        kid = jwt.get_unverified_header(token)['kid']
        return public_keys.get(kid)

    except tuple(expected_errors) as error:
        message = expected_errors[error.__class__]
        raise AuthenticationRequiredError(message)


def get_key():
    """
    Get authorization token and validate its signature against the public key
    from /.well-known/jwks endpoint
    """
    expected_errors = {
        KeyError: WRONG_PAYLOAD_STRUCTURE,
        AssertionError: JWK_HOST_MISSING,
        InvalidSignatureError: WRONG_KEY,
        DecodeError: WRONG_JWT_STRUCTURE,
        InvalidAudienceError: WRONG_AUDIENCE,
        TypeError: KID_NOT_FOUND
    }

    token = get_auth_token()
    try:
        jwks_host = jwt.decode(
            token, options={'verify_signature': False}).get('jwks_host')
        assert jwks_host
        key = get_public_key(jwks_host, token)
        aud = request.url_root
        payload = jwt.decode(
            token, key=key, algorithms=['RS256'], audience=[aud.rstrip('/')]
        )

        set_ctr_entities_limit(payload)
        current_app.config['GTI_ALLOW_TEST_ACCOUNTS'] = \
            payload['GTI_ALLOW_TEST_ACCOUNTS']

        return payload['key']
    except tuple(expected_errors) as error:
        message = expected_errors[error.__class__]
        raise AuthenticationRequiredError(message)


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
