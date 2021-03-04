from abc import ABC, abstractmethod
from collections import namedtuple
from typing import Dict, Any, Optional, List
from urllib.parse import quote_plus, urlparse
from uuid import uuid4

from flask import current_app


JSON = Dict[str, Any]


class Mapping(ABC):

    @classmethod
    @abstractmethod
    def map(cls, *args, **kwargs) -> JSON:
        pass


CTIM_DEFAULTS = {
    'schema_version': '1.0.17',
}


def transient_id(entity, uuid=None):
    if uuid is None:
        uuid = uuid4()
    return f"transient:{entity['type']}-{uuid}"


Observable = namedtuple('Observable', ['type', 'value'])


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

        sighting['id'] = transient_id(sighting)

        sighting['observed_time'] = {
            'start_time': event['timestamp']
        }
        sighting['observed_time']['end_time'] = (
            sighting['observed_time']['start_time']
        )

        details = cls._details(event)
        if details:
            sighting['data'] = details

        sighting['description'] = f"- Event: `{event['event_type'].upper()}`"
        if 'detection' in event:
            sighting['description'] += '\n' + (
                f"- Rule: `{event['detection']['rule']['name']}`"
            )

        sighting['external_ids'] = [event['uuid']]
        if 'detection' in event:
            sighting['external_ids'].append(
                event['detection']['rule']['uuid']
            )

        sighting['external_references'] = [{
            'source_name': sighting['source'],
            'description': '\n'.join([
                '- Represents the UUID of the given event.',
                '- Links to a UI search page querying for that particular '
                'event by its UUID.',
            ]),
            'external_id': event['uuid'],
            'url': current_app.config['GTI_UI_SEARCH_URL'].format(
                query=quote_plus(f"uuid = '{event['uuid']}'"),
            ),
        }]
        if 'detection' in event:
            sighting['external_references'].append({
                'source_name': sighting['source'],
                'description': '\n'.join([
                    '- Represents the UUID of a rule matching the given '
                    'event.',
                    '- Links to a UI page describing that specific rule along '
                    'with providing some summary over its history.',
                    '- Includes the UUID of an account associated with that '
                    'particular detection.',
                ]),
                'external_id': event['detection']['rule']['uuid'],
                'url': current_app.config['GTI_UI_RULE_ACCOUNT_URL'].format(
                    rule_uuid=event['detection']['rule']['uuid'],
                    account_uuid=event['detection']['account_uuid'],
                ),
            })

        sighting['observables'] = [event['observable']]

        relations = cls._relations(sighting['source'], event)
        if relations:
            sighting['relations'] = relations

        sighting['sensor'] = event['sensor_id']

        if 'detection' in event:
            sighting['severity'] = (
                cls.SEVERITY_MAPPING[event['detection']['rule']['severity']]
            )

        sighting['source_uri'] = sighting['external_references'][-1]['url']

        targets = cls._targets(sighting['observed_time'], event)
        if targets:
            sighting['targets'] = targets

        return sighting

    @staticmethod
    def _details(event) -> Optional[JSON]:
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

        details = None

        if columns and rows:
            details = {
                'columns': columns,
                'rows': rows,
            }

        return details

    @staticmethod
    def _relations(origin, event) -> Optional[List[JSON]]:
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
                },
            })

        if 'src' in event and 'dst' in event:
            append_relation(
                Observable('ip', event['src']['ip']),
                'Connected_To',
                Observable('ip', event['dst']['ip']),
            )

        if event['event_type'] == 'dns':
            if event['query']:
                domain = event['query']['domain']

                append_relation(
                    Observable('ip', event['src']['ip']),
                    'Queried_For',
                    Observable('domain', domain),
                )

                if event['answers']:
                    for answer in event['answers']:
                        if 'ip' in answer:
                            append_relation(
                                Observable('domain', domain),
                                'Resolved_To',
                                Observable('ip', answer['ip']),
                            )

        if event['event_type'] == 'http':
            if event['user_agent']:
                for loc, relation in [
                    ('src', 'Sent_From'),
                    ('dst', 'Sent_To'),
                ]:
                    append_relation(
                        Observable('user_agent', event['user_agent']),
                        relation,
                        Observable('ip', event[loc]['ip']),
                    )

            if event['host'] and event['host'].get('domain'):
                append_relation(
                    Observable('domain', event['host']['domain']),
                    'Resolved_To',
                    Observable('ip', event['dst']['ip']),
                )

            if event['uri']:
                # Don't rely on Gigamon and parse the provided URL into a named
                # tuple of its components by ourselves.
                # Make sure to also fill the main components (if missing) in
                # order to reconstruct the full URL.
                # Assume that the URL contains at least the path, but the host
                # and the scheme can be absent.
                components = urlparse(event['uri']['uri'], scheme='http')
                if not components.netloc:
                    host = event['host'] or {}
                    host = host.get('domain') or host.get('ip') or ''
                    components = components._replace(netloc=host)

                url = components.geturl()

                append_relation(
                    Observable('ip', event['src']['ip']),
                    'Connected_To',
                    Observable('url', url),
                )

                append_relation(
                    Observable('url', url),
                    'Hosted_On',
                    Observable('ip', event['dst']['ip']),
                )

            if event['files']:
                for loc, relation in (
                    [
                        ('src', 'Downloaded_To'),
                        ('dst', 'Downloaded_From'),
                    ]
                    if event['method'] == 'GET' else
                    [
                        ('src', 'Uploaded_From'),
                        ('dst', 'Uploaded_To'),
                    ]
                ):
                    for file in event['files']:
                        for hash_type in ['md5', 'sha1', 'sha256']:
                            if file.get(hash_type):
                                append_relation(
                                    Observable(hash_type, file[hash_type]),
                                    relation,
                                    Observable('ip', event[loc]['ip']),
                                )

        if event['event_type'] == 'x509':
            if event['observable']['type'] == 'domain':
                append_relation(
                    Observable('domain', event['observable']['value']),
                    'SAN_DNS_For',
                    Observable('ip', event['dst']['ip']),
                )

        return relations or None

    @staticmethod
    def _targets(observed_time, event) -> Optional[List[JSON]]:
        device = None

        for loc in ['src', 'dst']:
            if loc in event and event[loc]['internal']:
                device = event[loc]
                break

        if device is None:
            return None

        observables = [{'type': 'ip', 'value': device['ip']}]

        if 'dhcp' in device:
            for record in device['dhcp']:
                if record['account_code'] == event['customer_id']:
                    if record['hostname']:
                        observables.append(
                            {'type': 'hostname', 'value': record['hostname']}
                        )
                    if record['mac']:
                        observables.append(
                            {'type': 'mac_address', 'value': record['mac']}
                        )
                    break

        return [{
            'observables': observables,
            'observed_time': observed_time,
            'type': 'endpoint',
        }]


class Indicator(Mapping):
    DEFAULTS = {
        'type': 'indicator',
        'producer': 'Gigamon ThreatINSIGHT',
        'source': 'Gigamon ThreatINSIGHT',
        **CTIM_DEFAULTS
    }

    CONFIDENCE_MAPPING = {
        'high': 'High',
        'moderate': 'Medium',
        'low': 'Low',
    }

    SEVERITY_MAPPING = {
        'high': 'High',
        'moderate': 'Medium',
        'low': 'Low',
    }

    @classmethod
    def map(cls, rule: JSON) -> JSON:
        indicator: JSON = cls.DEFAULTS.copy()

        indicator['id'] = transient_id(indicator, uuid=rule['uuid'])

        indicator['valid_time'] = {'start_time': rule['created']}

        indicator['confidence'] = cls.CONFIDENCE_MAPPING[rule['confidence']]

        indicator['description'] = rule['description']

        indicator['external_ids'] = [rule['uuid']]

        indicator['external_references'] = [{
            'source_name': indicator['source'],
            'description': '\n'.join([
                '- Represents the UUID of the given rule.',
                '- Links to a UI page describing that specific rule along '
                'with providing some summary over its history.',
            ]),
            'external_id': rule['uuid'],
            'url': current_app.config['GTI_UI_RULE_URL'].format(
                rule_uuid=rule['uuid'],
            ),
        }]

        indicator['severity'] = cls.SEVERITY_MAPPING[rule['severity']]

        indicator['short_description'] = rule['name']

        indicator['source_uri'] = indicator['external_references'][0]['url']

        indicator['tags'] = [rule['category']]

        indicator['title'] = rule['name']

        return indicator


class Relationship(Mapping):
    DEFAULTS = {
        'type': 'relationship',
        'relationship_type': 'sighting-of',
        **CTIM_DEFAULTS
    }

    @classmethod
    def map(cls, sighting: JSON, indicator: JSON) -> JSON:
        relationship: JSON = cls.DEFAULTS.copy()

        relationship['id'] = transient_id(relationship)

        relationship['source_ref'] = sighting['id']

        relationship['target_ref'] = indicator['id']

        return relationship
