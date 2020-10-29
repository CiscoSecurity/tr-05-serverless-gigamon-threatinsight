import pytest
from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from tests.functional.tests.constants import MODULE_NAME


@pytest.mark.parametrize(
    'observable_type, observable',
    (('ip', '23.23.23.23'),
     ('domain', 'some.ml'),
     ('sha256',
      '36e60d1e07cbaccd8dfdad293e08442389a1525e2fa69fe1f3f781c22b90295b'),
     ('md5', '44d19c7592b61bfd3104c116950aa779'),
     ('sha1', '7d9862859cb4e36a5d57545fcf954881d94aaf3b'))
)
def test_positive_smoke_observe_observables_empty_observables(
        module_headers, observable, observable_type):
    """Perform testing for enrich observe observables endpoint to check that
     observable, on which Gigamon ThreatINSIGHT module doesn't have
     information, will return empty data

    ID: CCTRI-1695-dfc0dce8-6ed3-4c8d-a1b1-ce9675ce15f9

    Steps:
        1. Send request to enrich observe observable endpoint


    Expectedresults:
        1. Check that data in response body contains empty dict from Gigamon
        ThreatINSIGHT module

    Importance: Critical
    """
    observables = [{'type': observable_type, 'value': observable}]
    response_from_all_modules = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )

    response_from_gigamon = get_observables(response_from_all_modules, MODULE_NAME)

    assert response_from_gigamon['module'] == MODULE_NAME
    assert response_from_gigamon['module_instance_id']
    assert response_from_gigamon['module_type_id']

    assert response_from_gigamon['data'] == {}
