from functools import partial

from flask import Blueprint, current_app

from api.mappings import Sighting
from api.schemas import ObservableSchema
from api.utils import get_json, jsonify_data, jsonify_errors, get_key
from api.workflow import get_events_for_observable

enrich_api = Blueprint('enrich', __name__)


get_observables = partial(get_json, schema=ObservableSchema(many=True))


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    # There are no verdicts to extract.
    return jsonify_data({})


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    observables, error = get_observables()

    if error:
        return jsonify_errors(error)

    observables = [
        observable
        for observable in observables
        if observable['type'] in current_app.config['GTI_ENTITY_TYPES']
    ]

    key = get_key()

    sightings = []

    for observable in observables:
        events, error = get_events_for_observable(key, observable)

        if error:
            return jsonify_errors(error)

        sightings.extend(
            Sighting.map(event) for event in events
        )

    data = {}

    def format_docs(docs):
        return {'count': len(docs), 'docs': docs}

    if sightings:
        data['sightings'] = format_docs(sightings)

    return jsonify_data(data)


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    # There are no links to show.
    return jsonify_data([])
