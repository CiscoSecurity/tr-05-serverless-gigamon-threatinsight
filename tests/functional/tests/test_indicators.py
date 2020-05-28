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
def test_positive_indicators(module_headers, observable, observable_type):
    """Perform testing for enrich observe observables endpoint to check indicators
    of Gigamon ThreatINSIGHT module

    ID: CCTRI-1094-fb59a541-a42e-41fc-b859-52a1b564c14e

    Steps:
        1. Send request to enrich observe observable endpoint and check
        indicators


    Expectedresults:
        1. Check that data in response body contains indicators entity
        with needed fields ThreatINSIGHT module

    Importance: Critical
    """
    observables = [{'type': observable_type, 'value': observable}]
    response = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    indicators = get_observables(
        response, 'Gigamon ThreatINSIGHT')['data']['indicators']
    confidence_and_severity_levels = ['High', 'Medium', 'Low']

    assert len(indicators['docs']) > 0

    for indicator in indicators['docs']:
        assert indicator['description']
        assert indicator['producer'] == 'Gigamon ThreatINSIGHT'
        assert indicator['schema_version']
        assert indicator['type'] == 'indicator'
        assert indicator['source'] == 'Gigamon ThreatINSIGHT'
        assert indicator['short_description']
        assert indicator['title']
        assert indicator['confidence'] in confidence_and_severity_levels
        assert indicator['severity'] in confidence_and_severity_levels
        assert indicator['id'].startswith('transient:')
        assert indicator['valid_time']['start_time']
        assert indicator['external_ids']
        assert indicator['tags']
        assert indicator['source_uri'].startswith('https://portal.icebrg.io/')

        for external_reference in indicator['external_references']:
            assert external_reference['description']
            assert external_reference['external_id'] in (
                   indicator['external_ids'])
            assert external_reference['source_name'] == indicator['source']
            assert external_reference['url'].startswith(
                  'https://portal.icebrg.io/')

    assert indicators['count'] == len(indicators['docs'])
