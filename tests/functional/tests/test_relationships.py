from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
import pytest


@pytest.mark.parametrize(
    'observable_type, observable',
    (('ip', '45.77.51.101'),
     ('domain', 'securecorp.club'),
     ('sha256',
      '9ffc7e4333d3be11b244d5f83b02ebcd194a671539f7faf1b5597d9209cc25c3'),
     )
)
def test_positive_relationships(module_headers, observable, observable_type):
    """Perform testing for enrich observe observables endpoint to check
    relationships of Gigamon ThreatINSIGHT module

    ID: CCTRI-1094-fb59a541-a42e-41fc-b859-52a1b564c14e

    Steps:
        1. Send request to enrich observe observable endpoint and check
        relationships


    Expectedresults:
        1. Check that data in response body contains relationships entity
        with needed fields ThreatINSIGHT module

    Importance: Critical
    """
    observables = [{'type': observable_type, 'value': observable}]
    response = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    gigamon_module_data = get_observables(
        response, 'Gigamon ThreatINSIGHT')['data']
    relationships = gigamon_module_data['relationships']
    indicators = gigamon_module_data['indicators']
    sightings = gigamon_module_data['sightings']
    indicators_ids = frozenset(
        indicator['id'] for indicator in indicators['docs'])
    sightings_ids = frozenset(
        sighting['id'] for sighting in sightings['docs'])

    assert len(relationships['docs']) > 0

    for relationship in relationships['docs']:
        assert relationship['schema_version']
        assert relationship['target_ref'].startswith('transient:')
        assert relationship['target_ref'] in indicators_ids
        assert relationship['type'] == 'relationship'
        assert relationship['source_ref'].startswith('transient:')
        assert relationship['source_ref'] in sightings_ids
        assert relationship['id'].startswith('transient:')
        assert relationship['relationship_type'] == 'sighting-of'

    assert relationships['count'] == len(relationships['docs'])
