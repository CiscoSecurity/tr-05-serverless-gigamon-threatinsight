import os

from version import VERSION


class Config:
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY', '')

    CTR_USER_AGENT = (
        'Cisco Threat Response Integrations '
        '<tr-integrations-support@cisco.com>'
    )

    CTR_ENTITIES_LIMIT_DEFAULT = 100

    try:
        CTR_ENTITIES_LIMIT = int(os.environ['CTR_ENTITIES_LIMIT'])
        assert CTR_ENTITIES_LIMIT > 0
    except (KeyError, ValueError, AssertionError):
        CTR_ENTITIES_LIMIT = CTR_ENTITIES_LIMIT_DEFAULT

    CTR_ENTITIES_LIMIT_MAX = 1000

    if CTR_ENTITIES_LIMIT > CTR_ENTITIES_LIMIT_MAX:
        CTR_ENTITIES_LIMIT = CTR_ENTITIES_LIMIT_MAX

    GTI_OBSERVABLE_TYPES = {
        'ip': 'IP',
        'domain': 'domain',
        'md5': 'MD5',
        'sha1': 'SHA1',
        'sha256': 'SHA256',
    }

    GTI_TEST_ENTITY = '8.8.8.8'

    GTI_API_FAMILY_URLS = {
        'detection': 'https://detections.icebrg.io/v1/',
        'event': 'https://events.icebrg.io/v2/',
        'entity': 'https://entity.icebrg.io/v2/',
    }

    GTI_UI_RULE_URL = (
        'https://portal.icebrg.io/detections/rules/'
        '{rule_uuid}?account_uuid={account_uuid}'
    )

    GTI_UI_SEARCH_URL = 'https://portal.icebrg.io/search?query={query}'
