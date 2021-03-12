import json


class Config:
    settings = json.load(open('container_settings.json', 'r'))
    VERSION = settings["VERSION"]

    CTR_USER_AGENT = (
        'SecureX Threat Response Integrations '
        '<tr-integrations-support@cisco.com>'
    )

    CTR_ENTITIES_LIMIT_DEFAULT = 100

    CTR_ENTITIES_LIMIT_MAX = 1000

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

    GTI_UI_RULE_URL = 'https://portal.icebrg.io/detections/rules/{rule_uuid}'
    GTI_UI_RULE_ACCOUNT_URL = GTI_UI_RULE_URL + '?account_uuid={account_uuid}'

    GTI_UI_SEARCH_URL = 'https://portal.icebrg.io/search?query={query}'

    GTI_TEST_ACCOUNTS = {
        'dmo', '6bc3d2f1-af77-4236-a9db-17dacd06e4d9',  # Demo
        'chg', 'f6f6f836-8bcd-4f5d-bd61-68d303c4f634',  # Training
    }
