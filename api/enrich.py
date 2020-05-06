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

    observable_types = current_app.config['GTI_OBSERVABLE_TYPES']

    observables = [
        observable
        for observable in observables
        if observable['type'] in observable_types
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
    observables, error = get_observables()

    if error:
        return jsonify_errors(error)

    observable_types = current_app.config['GTI_OBSERVABLE_TYPES']

    def type_of(observable):
        return observable_types[observable['type']]

    url_template = current_app.config['GTI_UI_SEARCH_URL']

    data = [
        {
            'id': 'ref-gti-search-{type}-{value}'.format(**observable),
            'title': f'Search for this {type_of(observable)}',
            'description': (
                f'Lookup this {type_of(observable)} '
                'on Gigamon ThreatINSIGHT'
            ),
            'url': url_template.format(entity=observable['value']),
            'categories': ['Search', 'Gigamon ThreatINSIGHT'],
        }
        for observable in observables
        if observable['type'] in observable_types
    ]

    return jsonify_data(data)
