from flask import Blueprint, current_app

from api.integration import get_events_for_entity
from api.utils import get_key, jsonify_errors, jsonify_data

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    key = get_key()

    # Use some supported entity just to check that the GTI API key is valid.
    entity = current_app.config['GTI_TEST_ENTITY']
    _, error = get_events_for_entity(key, entity)

    if error:
        return jsonify_errors(error)
    else:
        return jsonify_data({'status': 'ok'})
