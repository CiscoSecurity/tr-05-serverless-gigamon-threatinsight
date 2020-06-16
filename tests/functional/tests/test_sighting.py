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
    """Perform testing for enrich observe observables endpoint to check
    sightings of Gigamon ThreatINSIGHT module

    ID: CCTRI-894-cfffca7f-cdd9-4ead-8d3d-6d757246137c

    Steps:
        1. Send request to enrich observe observable endpoint and check
        sighting


    Expectedresults:
        1. Response body contains sightings entity with needed fields from
        ThreatINSIGHT module

    Importance: Critical
    """
    observables = [{'type': observable_type, 'value': observable}]
    response_from_all_modules = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    sightings = get_observables(
        response_from_all_modules, 'Gigamon ThreatINSIGHT'
    )['data']['sightings']
    confidence_levels = ['High', 'Info', 'Low', 'Medium', 'None', 'Unknown']
    targets_observables_types = ['ip', 'hostname', 'mac_address']

    assert len(sightings['docs']) > 0

    for sighting in sightings['docs']:
        assert sighting['description']
        assert sighting['relations']
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

        assert sighting['sensor']
        assert sighting['internal'] is True
        assert sighting['targets'][0]['type'] == 'endpoint'
        assert sighting['targets'][0]['observed_time']['start_time']
        for observable_type in sighting['targets'][0]['observables']:
            assert observable_type['type'] in targets_observables_types

    assert sightings['count'] == len(sightings['docs'])


@pytest.mark.parametrize(
    'observable_type, observable',
    (('ip', '45.77.51.101'),
     ('domain', 'securecorp.club'),
     ('sha256',
      '9ffc7e4333d3be11b244d5f83b02ebcd194a671539f7faf1b5597d9209cc25c3'),
     ('md5', '3319b1a422c785c221050f1152ad77cb'),
     ('sha1', '2d7177f8466d82e28150572584928278ba72d435'))
)
def test_positive_sighting_relation(module_headers, observable,
                                    observable_type):
    """Perform testing for enrich observe observables endpoint to check
    relationships in sighting of Gigamon ThreatINSIGHT module

    ID: CCTRI-1174-fb8d55ae-0352-4170-9b17-ddf49fa81783

    Steps:
        1. Send request to enrich observe observable endpoint and check
        relationships in sighting


    Expectedresults:
        1. Response body contains relationships in sightings entity with needed
        fields from Gigamon ThreatINSIGHT module

    Importance: Critical
    """
    observables = [{'type': observable_type, 'value': observable}]
    response_from_all_modules = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    sightings = get_observables(
        response_from_all_modules, 'Gigamon ThreatINSIGHT'
    )['data']['sightings']
    relations_types = [
        'Connected_To', 'Sent_From', 'Sent_To',
        'Resolved_To', 'Hosted_On', 'Queried_For',
        'Downloaded_To', 'Downloaded_From',
        'Uploaded_From', 'Uploaded_To',
    ]
    for sighting in sightings['docs']:
        if 'HTTP' in sighting['description'].splitlines()[0]:
            http_relations = {
                relation['relation'] for relation in sighting['relations']
            }
            assert 'Connected_To' in http_relations
            download_relations = {'Downloaded_To', 'Downloaded_From'}
            upload_relations = {'Uploaded_From', 'Uploaded_To'}
            intersection_relations = http_relations & (
                    download_relations | upload_relations)
            assert not intersection_relations or (
                    intersection_relations == download_relations) or (
                    intersection_relations == upload_relations)

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


def test_positive_sighting_x509(module_headers):
    """Perform testing for Gigamon ThreatINSIGHT module sightings functionality
    for x509 event types specifically

    ID: CCTRI-1125-82b45fee-9266-4793-9642-b89a324b8e26

    Steps:
        1. Send request to enrich observe observable endpoint and check
        sighting. Use observables that contains sightings for x509 event type


    Expectedresults:
        1. Response body contains sightings entity with expected data for x509
            event type

    Importance: Critical
    """
    observables = [{'type': 'domain', 'value': 'wp.com'}]
    response_from_all_modules = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    sightings = get_observables(
        response_from_all_modules, 'Gigamon ThreatINSIGHT'
    )['data']['sightings']

    assert len(sightings['docs']) > 0
    assert [
        sighting for sighting in sightings['docs']
        if 'Event: `X509`' in sighting['description']
    ], 'There are no sightings with necessary event type'

    for sighting in sightings['docs']:
        if 'Event: `X509`' in sighting['description']:
            relation = [
                r for r in sighting['relations']
                if r['relation'] == 'SAN_DNS_For'
            ]
            assert relation
            assert relation[0]['origin'] == 'Gigamon ThreatINSIGHT'
            assert relation[0]['source'] == observables[0]
            assert relation[0]['related']['type'] == 'ip'
            assert relation[0]['related']['value']
    assert sightings['count'] == len(sightings['docs'])
