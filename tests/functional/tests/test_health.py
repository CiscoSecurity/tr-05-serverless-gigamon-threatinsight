from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_post_health


def test_positive_smoke_enrich_health(module_headers):
    """Perform testing for enrich health endpoint to check status of Gigamon
    ThreatINSIGHT module

    ID: CCTRI-652-df76fdb9-0e57-45a3-b312-2d2036e14b48

    Steps:
        1. Send request to enrich health endpoint

    Expectedresults:
        1. Check that data in response body contains status Ok from Gigamon
            ThreatINSIGHT module

    Importance: Critical
    """
    response = enrich_post_health(
        **{'headers': module_headers}
    )['data']
    health = get_observables(response, 'Gigamon ThreatINSIGHT')
    assert health['data'] == {'status': 'ok'}
