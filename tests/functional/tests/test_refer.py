import pytest
from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_refer_observables
from tests.functional.tests.constants import (
    MODULE_NAME,
    GIGAMON_URL,
    OBSERVABLE_HUMAN_READABLE_NAME
)


@pytest.mark.parametrize(
    'observable_type, observable',
    (('ip', '45.77.51.101'),
     ('domain', 'securecorp.club'),
     ('sha256',
      '9ffc7e4333d3be11b244d5f83b02ebcd194a671539f7faf1b5597d9209cc25c3'),
     ('md5', '3319b1a422c785c221050f1152ad77cb'),
     ('sha1', '2d7177f8466d82e28150572584928278ba72d435')
     )
)
def test_positive_refer_observables(module_headers, observable,
                                    observable_type):
    """Perform testing for enrich refer observables endpoint to check response
     from Gigamon ThreatINSIGHT module

    ID: CCTRI-894-1cbaf12e-b4db-4d42-bbd5-ff7666b46ccc

    Steps:
        1. Send request to enrich refer observables endpoint and check response


    Expectedresults:
        1. Response body contains refer entity with needed fields from Gigamon
         ThreatINSIGHT module

    Importance: Critical
    """
    observables = [{'type': observable_type, 'value': observable}]
    response_from_all_modules = enrich_refer_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    response_from_gigamon_module = get_observables(
        response_from_all_modules, MODULE_NAME)

    assert response_from_gigamon_module['module'] == MODULE_NAME
    assert response_from_gigamon_module['module_instance_id']
    assert response_from_gigamon_module['module_type_id']

    assert response_from_gigamon_module['id'] == (
        f'ref-gti-search-{observable_type}-{observable}')
    assert response_from_gigamon_module['title'] == (
        f'Search for this {OBSERVABLE_HUMAN_READABLE_NAME[observable_type]}')
    assert (response_from_gigamon_module['description']) == (
        f'Lookup this {OBSERVABLE_HUMAN_READABLE_NAME[observable_type]} on '
        f'{MODULE_NAME}')
    assert response_from_gigamon_module['categories'] == [
        MODULE_NAME,
        'Search'
    ]
    assert response_from_gigamon_module['url'] == (
        f'{GIGAMON_URL}/search?query={observable}')
