import pytest
from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from tests.functional.tests.constants import (
    MODULE_NAME,
    GIGAMON_URL,
    CONFIDENCE,
    SEVERITY,
    CTR_ENTITIES_LIMIT
)


@pytest.mark.parametrize(
    'observable_type, observable',
    (('ip', '45.77.51.101'),
     ('domain', 'securecorp.club'),
     ('sha256',
      '9ffc7e4333d3be11b244d5f83b02ebcd194a671539f7faf1b5597d9209cc25c3'),
     )
)
def test_positive_indicators(module_headers, observable, observable_type):
    """Perform testing for enrich observe observables endpoint to check
    indicators of Gigamon ThreatINSIGHT module

    ID: CCTRI-1094-fb59a541-a42e-41fc-b859-52a1b564c14e

    Steps:
        1. Send request to enrich observe observable endpoint and check
        indicators


    Expectedresults:
        1. Response body contains indicators entity with needed fields from
        ThreatINSIGHT module

    Importance: Critical
    """
    observables = [{'type': observable_type, 'value': observable}]
    response_from_all_modules = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    response_from_gigamon_module = get_observables(
        response_from_all_modules, MODULE_NAME)

    assert response_from_gigamon_module['module'] == MODULE_NAME
    assert response_from_gigamon_module['module_instance_id']
    assert response_from_gigamon_module['module_type_id']

    indicators = response_from_gigamon_module['data']['indicators']
    assert len(indicators['docs']) > 0

    for indicator in indicators['docs']:
        assert indicator['description']
        assert indicator['producer'] == MODULE_NAME
        assert indicator['schema_version']
        assert indicator['type'] == 'indicator'
        assert indicator['source'] == MODULE_NAME
        assert indicator['short_description']
        assert indicator['title']
        assert indicator['confidence'] in CONFIDENCE
        assert indicator['severity'] in SEVERITY
        assert indicator['external_ids']
        assert indicator['id'] == (
            f"transient:indicator-{indicator['external_ids'][0]}"
        )
        assert indicator['valid_time']['start_time']
        assert 'tags' in indicator
        assert indicator['source_uri'] == (
            f'{GIGAMON_URL}/detections/rules/{indicator["external_ids"][0]}'
        )

        for external_reference in indicator['external_references']:
            assert external_reference['description']
            assert external_reference['external_id'] == (
                indicator['external_ids'][0]
            )
            assert external_reference['source_name'] == MODULE_NAME
            assert external_reference['url'] == (
                f'{GIGAMON_URL}'
                f'/detections/rules/{indicator["external_ids"][0]}'
            )

    assert indicators['count'] == len(indicators['docs']) <= CTR_ENTITIES_LIMIT
