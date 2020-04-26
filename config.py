import os

from version import VERSION


class Config:
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY', '')

    CTR_USER_AGENT = (
        'Cisco Threat Response Integrations '
        '<tr-integrations-support@cisco.com>'
    )

    GTI_OBSERVABLE_TYPES = {
        'ip': 'IP',
        'domain': 'Domain',
        'md5': 'MD-5',
        'sha1': 'SHA-1',
        'sha256': 'SHA-256',
    }

    GTI_TEST_ENTITY = '8.8.8.8'

    GTI_API_FAMILY_URLS = {
        'detection': 'https://detections.icebrg.io/v1/',
        'event': 'https://events.icebrg.io/v2/',
    }

    GTI_UI_URL = 'https://portal.icebrg.io/detections/rules/{rule_uuid}'
