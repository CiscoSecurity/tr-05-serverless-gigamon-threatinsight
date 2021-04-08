import pytest
from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from tests.functional.tests.constants import (
    MODULE_NAME,
    CTR_ENTITIES_LIMIT
)


@pytest.mark.parametrize(
    'observable_type, observable',
    (('ip', '45.77.51.101'),
     # ('domain', 'securecorp.club'),
     ('sha256',
      '9ffc7e4333d3be11b244d5f83b02ebcd194a671539f7faf1b5597d9209cc25c3'),
     )
)
def test_positive_relationships(module_headers, observable, observable_type):
    """Perform testing for enrich observe observables endpoint to check
    relationships of Gigamon ThreatINSIGHT module

    ID: CCTRI-1094-52303f90-0ac9-42e5-80b7-aab5b5d83f47

    Steps:
        1. Send request to enrich observe observable endpoint and check
        relationships


    Expectedresults:
        1. Response body contains relationships entity with needed fields from
        ThreatINSIGHT module

    Importance: Critical
    """
    observables = [{'type': observable_type, 'value': observable}]
    response_from_all_modules = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )
    response_from_gigamon = get_observables(
        response_from_all_modules, MODULE_NAME)

    assert response_from_gigamon['module']
    assert response_from_gigamon['module_instance_id']
    assert response_from_gigamon['module_type_id']

    relationships = response_from_gigamon['data']['relationships']
    indicators = response_from_gigamon['data']['indicators']
    sightings = response_from_gigamon['data']['sightings']
    indicators_ids = frozenset(
        indicator['id'] for indicator in indicators['docs'])
    sightings_ids = frozenset(
        sighting['id'] for sighting in sightings['docs'])

    assert len(relationships['docs']) > 0

    for relationship in relationships['docs']:
        assert relationship['schema_version']
        assert relationship['target_ref'].startswith('transient:indicator')
        assert relationship['target_ref'] in indicators_ids
        assert relationship['type'] == 'relationship'
        assert relationship['source_ref'].startswith('transient:sighting')
        assert relationship['source_ref'] in sightings_ids
        assert relationship['id'].startswith('transient:relationship')
        assert relationship['relationship_type'] == 'sighting-of'

    assert relationships['count'] == (
        len(relationships['docs'])) <= (
        CTR_ENTITIES_LIMIT
    )
