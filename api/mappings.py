import abc
from typing import Dict, Any
from uuid import uuid4

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
        **CTIM_DEFAULTS
    }

    SEVERITY_MAPPING = {
        'high': 'High',
        'moderate': 'Medium',
        'low': 'Low',
    }

    @classmethod
    def map(cls, event: JSON) -> JSON:
        sighting: JSON = cls.DEFAULTS.copy()

        sighting['id'] = f'transient:{uuid4()}'

        sighting['observed_time'] = {'start_time': event['timestamp']}

        if 'detection' in event:
            sighting['data'] = {
                'columns': [
                    {'name': 'Impacted Devices', 'type': 'integer'},
                    {'name': 'Indicator Values', 'type': 'integer'},
                ],
                'rows': [
                    [
                        event['detection']['summary']['impacted_devices'],
                        event['detection']['summary']['indicator_values'],
                    ],
                ]
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

        sighting['observables'] = [event['observable']]

        sighting['relations'] = cls._relations(sighting['source'], event)

        sighting['sensor'] = event['sensor_id']

        if 'detection' in event:
            sighting['severity'] = (
                cls.SEVERITY_MAPPING[event['detection']['rule']['severity']]
            )

        if 'detection' in event:
            sighting['source_uri'] = (
                current_app.config['GTI_UI_RULE_URL'].format(
                    rule_uuid=event['detection']['rule']['uuid'],
                    account_uuid=event['detection']['account_uuid'],
                )
            )

        sighting['targets'] = cls._targets(sighting['observed_time'], event)

        return sighting

    @staticmethod
    def _relations(origin, event):
        relations = []

        for source_obj, related_obj, relation in [
            ('src', 'dst', 'Connected_To'),
            ('dst', 'src', 'Connected_From'),
        ]:
            if event[source_obj]['internal']:
                relations.append({
                    'origin': origin,
                    'related': {
                        'type': 'ip',
                        'value': event[related_obj]['ip'],
                    },
                    'relation': relation,
                    'source': {
                        'type': 'ip',
                        'value': event[source_obj]['ip'],
                    },
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
