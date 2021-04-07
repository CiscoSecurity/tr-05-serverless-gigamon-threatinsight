from flask import Blueprint, current_app

from api.integration import get_events
from api.utils import get_key, jsonify_errors, jsonify_data

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    key = get_key()

    # Use some supported entity just to check that the GTI API key is valid.
    observable = current_app.config['GTI_TEST_ENTITY']
    _, error = get_events(key, observable)

    if error:
        return jsonify_errors(error)
    else:
        return jsonify_data({'status': 'ok'})
