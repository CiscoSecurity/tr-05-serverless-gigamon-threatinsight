from urllib.parse import quote

from flask import Blueprint, current_app

from api.utils import get_key, call_gti_api, jsonify_errors, jsonify_data

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    key = get_key()

    # Use some supported entity just to check that the GTI API key is valid.
    url = current_app.config['GTI_API_URLS']['entity']['summary'].format(
        entity=quote(current_app.config['GTI_TEST_ENTITY'], safe='')
    )
    _, error = call_gti_api(key, 'GET', url)

    if error:
        return jsonify_errors(error)
    else:
        return jsonify_data({'status': 'ok'})
