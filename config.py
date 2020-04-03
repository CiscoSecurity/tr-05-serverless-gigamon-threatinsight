import os

from version import VERSION


class Config:
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY', '')

    GTI_TEST_ENTITY = '8.8.8.8'

    GTI_API_URLS = {
        'entity': {
            'summary': 'https://entity.icebrg.io/v1/entity/{entity}/summary',
        },
    }

    GTI_USER_AGENT = (
        'Cisco Threat Response Integrations '
        '<tr-integrations-support@cisco.com>'
    )
