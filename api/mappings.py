import abc
from collections import namedtuple
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


Observable = namedtuple('Observable', ('type', 'value'))


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

        sighting['data'] = cls._details(event)

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
    def _details(event):
        columns = []
        rows = []

        if event['event_type'] == 'flow':
            columns.extend([
                {'name': 'flow_state', 'type': 'string'},
                {'name': 'proto', 'type': 'string'},
                {'name': 'service', 'type': 'string'},
                {'name': 'total_pkts', 'type': 'integer'},
            ])
            rows.append([
                event['flow_state'],
                event['proto'],
                event['service'],
                event['total_pkts'],
            ])

        if event['event_type'] == 'dns':
            columns.extend([
                {'name': 'qtype', 'type': 'integer'},
                {'name': 'qtype_name', 'type': 'string'},
                {'name': 'rcode', 'type': 'integer'},
                {'name': 'rcode_name', 'type': 'string'},
                # Use 'string' instead of 'boolean' (not supported yet).
                {'name': 'rejected', 'type': 'string'},
            ])
            rows.append([
                event['qtype'],
                event['qtype_name'],
                event['rcode'],
                event['rcode_name'],
                # False -> 'false', True -> 'true'.
                str(event['rejected']).lower(),
            ])

        if event['event_type'] == 'http':
            columns.extend([
                {'name': 'method', 'type': 'string'},
                {'name': 'status_code', 'type': 'integer'},
                {'name': 'status_msg', 'type': 'string'},
                {'name': 'files', 'type': 'integer'},
            ])
            rows.append([
                event['method'],
                event['status_code'],
                event['status_msg'],
                len(event['files'] or []),
            ])

        if event['event_type'] == 'ssh':
            columns.extend([
                {'name': 'direction', 'type': 'string'},
                {'name': 'client', 'type': 'string'},
                {'name': 'server', 'type': 'string'},
            ])
            rows.append([
                event['direction'],
                event['client'],
                event['server'],
            ])

        if event['event_type'] == 'suricata':
            columns.extend([
                {'name': 'sig_name', 'type': 'string'},
                {'name': 'sig_category', 'type': 'string'},
                {'name': 'sig_id', 'type': 'integer'},
                {'name': 'sig_rev', 'type': 'number'},
            ])
            rows.append([
                event['sig_name'],
                event['sig_category'],
                event['sig_id'],
                event['sig_rev'],
            ])

        if columns:
            # Add a bullet before each column (i.e. field) name for better
            # appearance on the UI.
            for column in columns:
                column['name'] = '•' + ' ' + column['name']

            # Add some "header" column for the event-specific details.
            columns.insert(0, {'name': 'Event Summary', 'type': 'string'})
            rows[0].insert(0, ' ')

        if 'detection' in event:
            # Make the detection-specific details come before the
            # event-specific ones to visually highlight the former from the
            # latter on the UI.
            # Add some "header" column for the detection-specific details.
            extra_columns = [
                {'name': 'Detection Summary', 'type': 'string'},
                {'name': 'Impacted Devices', 'type': 'integer'},
                {'name': 'Indicator Values', 'type': 'integer'},
            ]
            extra_row = [
                ' ',
                event['detection']['summary']['impacted_devices'],
                event['detection']['summary']['indicator_values'],
            ]

            columns = extra_columns + columns
            if rows:
                for index, row in enumerate(rows):
                    rows[index] = extra_row + row
            else:
                rows.append(extra_row)

        return {
            'columns': columns,
            'rows': rows,
        }

    @staticmethod
    def _relations(origin, event):
        relations = []

        def append_relation(
            source: Observable,
            relation: str,
            related: Observable,
        ) -> None:
            relations.append({
                'origin': origin,
                'related': {
                    'type': related.type,
                    'value': related.value,
                },
                'relation': relation,
                'source': {
                    'type': source.type,
                    'value': source.value,
                }
            })

        append_relation(
            Observable('ip', event['src']['ip']),
            'Connected_To',
            Observable('ip', event['dst']['ip']),
        )

        # TODO: come up with more possible relations of interest

        if event['event_type'] == 'dns':
            append_relation(
                Observable('ip', event['src']['ip']),
                'Queried',
                Observable('domain', event['query']['domain'])
            )

            if event['answers']:
                for answer in event['answers']:
                    append_relation(
                        Observable('domain', event['query']['domain']),
                        'Resolved_To',
                        Observable('ip', answer['ip'])
                    )

        if event['event_type'] == 'http':
            if event['user_agent']:
                append_relation(
                    Observable('user_agent', event['user_agent']),
                    'Sent_By',
                    Observable('ip', event['src']['ip']),
                )

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
