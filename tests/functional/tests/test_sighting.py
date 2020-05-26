from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
import pytest


@pytest.mark.parametrize(
    'observable_type, observable',
    (('ip', '45.77.51.101'),
     ('domain', 'securecorp.club'),
     ('sha256',
      '9ffc7e4333d3be11b244d5f83b02ebcd194a671539f7faf1b5597d9209cc25c3'),
     ('md5', '3319b1a422c785c221050f1152ad77cb'),
     ('sha1', '2d7177f8466d82e28150572584928278ba72d435'))
)
def test_positive_sighting(module_headers, observable, observable_type):
    """Perform testing for enrich observe observables endpoint to check sightings
    of Gigamon ThreatINSIGHT module

    ID: CCTRI-894-cfffca7f-cdd9-4ead-8d3d-6d757246137c

    Steps:
        1. Send request to enrich observe observable endpoint and check
        sighting


    Expectedresults:
        1. Check that data in response body contains sighting entity
        with needed fields ThreatINSIGHT module

    Importance: Critical
    """
    observables = [{'type': observable_type, 'value': observable}]
    response = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    sightings = get_observables(
        response, 'Gigamon ThreatINSIGHT')['data']['sightings']
    confidence_levels = ['High', 'Info', 'Low', 'Medium', 'None', 'Unknown']
    relations_types = [
        'Connected_To', 'Sent_From', 'Sent_To',
        'Resolved_To', 'Hosted_On', 'Queried_For'
    ]
    targets_observables_types = ['ip', 'hostname', 'mac_address']

    assert len(sightings['docs']) > 0

    for sighting in sightings['docs']:
        assert sighting['description']
        assert sighting['confidence'] in confidence_levels
        assert sighting['count'] == 1
        assert sighting['id'].startswith('transient:')
        assert sighting['observed_time']['start_time']
        assert sighting['schema_version']
        assert sighting['observables'][0] == observables[0]
        assert sighting['external_ids']
        assert sighting['type'] == 'sighting'
        assert sighting['source'] == 'Gigamon ThreatINSIGHT'
        assert sighting['source_uri'].startswith('https://portal.icebrg.io/')

        for external_reference in sighting['external_references']:
            assert external_reference['external_id'] in (
                   sighting['external_ids'])
            assert external_reference['source_name'] == sighting['source']
            assert external_reference['description']
            assert external_reference['url']

        for relation in sighting['relations']:
            assert relation['origin'] == 'Gigamon ThreatINSIGHT'
            assert relation['relation'] in relations_types
            assert relation['source']['value']
            assert relation['source']['type']
            assert relation['related']['value']
            assert relation['related']['type']
            if relation['relation'] == 'Hosted_On':
                assert relation['source']['value'].startswith('http') and (
                       relation['source']['type'] == 'url')

        assert sighting['sensor']
        assert sighting['internal'] is True
        assert sighting['targets'][0]['type'] == 'endpoint'
        assert sighting['targets'][0]['observed_time']['start_time']
        for observable_type in sighting['targets'][0]['observables']:
            assert observable_type['type'] in targets_observables_types

    assert sightings['count'] == len(sightings['docs'])
