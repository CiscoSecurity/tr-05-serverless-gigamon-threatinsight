from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from operator import itemgetter

from flask import current_app

from api.integration import (
    get_detections_for_entity,
    get_events_for_detection,
    get_events_for_entity,
)


def _get_events_for_detection(key, detection_uuid):
    from app import app

    # Run the original function in the context of the current app since this
    # helper function will be called in multiple separate worker threads.
    with app.app_context():
        return detection_uuid, get_events_for_detection(key, detection_uuid)


def _values(obj, path):
    """
    Extract all the values located on a particular path in a given object.

    The function returns a generator yielding one value at a time.
    If the path doesn't exist for the object, the function won't yield anything
    resulting in an empty generator.

    >>> list(_values({'x': {'y': [{'z': 1}, {'z': 2}, {'z': 3}]}}, ('x', 'y', 'z')))  # noqa: E501
    [1, 2, 3]
    """
    if not path:
        yield obj
        return

    key = path[0]
    if not (isinstance(obj, dict) and key in obj):
        return

    if isinstance(obj[key], list):
        for item in obj[key]:
            yield from _values(item, path[1:])
    else:
        yield from _values(obj[key], path[1:])


def get_events_for_observable(key, observable):
    entity = observable['value']

    detections, error = get_detections_for_entity(key, entity)

    if error:
        return None, error

    # Fetch all the detections for the given entity and then all the events for
    # each detection enriching them with some additional context along the way.

    events = []

    with ThreadPoolExecutor() as executor:
        futures = [
            executor.submit(_get_events_for_detection, key, detection['uuid'])
            for detection in detections
        ]

        for future in as_completed(futures):
            detection_uuid, (events_for_detection, error) = future.result()

            # Suppress any errors and continue processing.
            if error:
                events_for_detection = []

            detection = next(
                detection
                for detection in detections
                if detection['uuid'] == detection_uuid
            )

            indicator_field_paths = []

            indicator_values_by_indicator_type = defaultdict(set)

            for indicator in detection['indicators']:
                # E.g.
                # 'dst.ip' -> ('dst', 'ip'),
                # 'http:files.sha256' -> ('files', 'sha256'),
                # etc.
                indicator_field_path = tuple(
                    indicator['field'].split(':')[-1].split('.')
                )

                indicator_type = indicator_field_path[-1]
                if indicator_type in current_app.config['GTI_ENTITY_TYPES']:
                    indicator_field_paths.append(indicator_field_path)

                    indicator_values_by_indicator_type[
                        current_app.config['GTI_ENTITY_TYPES'][indicator_type]
                    ].update(indicator['values'])

            detection['summary'] = {
                indicator_type: len(indicator_values)
                for indicator_type, indicator_values
                in indicator_values_by_indicator_type.items()
            }

            for event in events_for_detection:
                if any(
                    entity in _values(event, indicator_field_path)
                    for indicator_field_path in indicator_field_paths
                ):
                    event['detection'] = detection
                    events.append(event)

    events.sort(key=itemgetter('timestamp'), reverse=True)

    # Fetch some of the most recent events for the given entity and merge them
    # to the already processed ones making sure to filter out any duplicates.

    events_for_entity, error = get_events_for_entity(key, entity)

    if error:
        return None, error

    uuids = frozenset(event['uuid'] for event in events)

    events.extend(
        event for event in events_for_entity
        if event['uuid'] not in uuids
    )

    for event in events:
        event['observable'] = observable

    # TODO: limit the number of events
    return events
