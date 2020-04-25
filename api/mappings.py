import abc
import uuid
from typing import Dict, Any

from flask import current_app


JSON = Dict[str, Any]


class Mapping(abc.ABC):

    @classmethod
    @abc.abstractmethod
    def map(cls, *args, **kwargs) -> JSON:
        pass


CTIM_DEFAULTS = {
    'schema_version': '1.0.16',
}


class Sighting(Mapping):
    DEFAULTS = {
        'type': 'sighting',
        'confidence': 'High',
        'count': 1,
        'internal': True,
        'source': 'Gigamon ThreatINSIGHT',
        # TODO: figure out with title
        # 'title': 'Found on Gigamon ThreatINSIGHT',
        **CTIM_DEFAULTS
    }

    @classmethod
    def map(cls, event: JSON) -> JSON:
        sighting: JSON = cls.DEFAULTS.copy()

        sighting['id'] = f'transient:{uuid.uuid4()}'

        sighting['observed_time'] = {'start_time': event['timestamp']}

        if 'detection' in event:
            sighting['data'] = {
                'columns': [
                    {'name': 'Indicator', 'type': 'string'},
                    {'name': 'Unique Values', 'type': 'integer'},
                ],
                'rows': list(event['detection']['summary'].items()),
            }

        sighting['description'] = '\n'.join(
            [f'- Event: `{event["event_type"].upper()}`.'] + (
                [f'- Rule: `{event["detection"]["rule"]["name"]}`.']
                if 'detection' in event else
                []
            )
        )

        sighting['external_ids'] = [event['uuid']] + (
            [event['detection']['rule']['uuid']]
            if 'detection' in event else
            []
        )

        # Each event is always enriched with its corresponding observable.
        sighting['observables'] = [event['observable']]

        # TODO: figure out with relations for each event type

        # sighting['resolution'] = 'detected'

        sighting['sensor'] = event['sensor_id']

        # sighting['severity'] = 'Unknown'

        if 'detection' in event:
            sighting['source_uri'] = current_app.config['GTI_UI_URL'].format(
                rule_uuid=event['detection']['rule']['uuid']
            )

        # TODO: figure out with targets for each event type
        if 'detection' in event:
            sighting['targets'] = [{
                'observables': [{
                    'type': 'ip',
                    'value': event['detection']['device_ip'],
                }],
                'observed_time': sighting['observed_time'],
                'type': 'endpoint',
            }]

        return sighting
