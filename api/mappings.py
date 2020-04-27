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

        sighting['relations'] = cls._relations(sighting['source'], event)

        sighting['sensor'] = event['sensor_id']

        if 'detection' in event:
            sighting['source_uri'] = current_app.config['GTI_UI_URL'].format(
                rule_uuid=event['detection']['rule']['uuid']
            )

        sighting['targets'] = cls._targets(sighting['observed_time'], event)

        return sighting

    @staticmethod
    def _relations(source, event):
        relations = []

        for src, dst in [('src', 'dst'), ('dst', 'src')]:
            if event[src]['internal']:
                relations.append({
                    'origin': source,
                    'related': {'type': 'ip', 'value': event[dst]['ip']},
                    'relation': 'Connected_To',
                    'source': {'type': 'ip', 'value': event[src]['ip']},
                })

        # TODO: come up with more possible relations of interest

        return relations

    @staticmethod
    def _targets(observed_time, event):
        ips = [
            event[loc]['ip']
            for loc in ['src', 'dst']
            if event[loc]['internal']
        ]

        entity = event['observable']['value']
        if entity in ips:
            # If the entity being looked for is one of the internal devices,
            # then move it to the end of the list to make the target look
            # better on the UI (it will be labeled by the other device if any).
            ips.sort(key=lambda ip: ip == entity)

        return [{
            'observables': [
                {'type': 'ip', 'value': ip}
                for ip in ips
            ],
            'observed_time': observed_time,
            'type': 'endpoint',
        }]
