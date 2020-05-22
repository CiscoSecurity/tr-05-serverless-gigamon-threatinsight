from contextlib import ExitStack
from unittest import mock

from api.workflow import get_events_for_observable

from .utils import load_fixture


def test_get_events_for_observable(client):
    def success(data):
        return data, None

    def submit(func, *args, **kwargs):
        future = mock.MagicMock()
        future.result = lambda: func(*args, **kwargs)
        return future

    def as_competed(futures):
        return futures

    with ExitStack() as stack:
        # 1. Arrange.

        get_detections_for_entity_mock = stack.enter_context(
            mock.patch('api.workflow.get_detections_for_entity')
        )

        detections = load_fixture('integration/detections_for_entity')

        get_detections_for_entity_mock.return_value = success(detections)

        stack.enter_context(
            mock.patch('api.workflow.ThreadPoolExecutor.submit')
        ).side_effect = submit

        stack.enter_context(
            mock.patch('api.workflow.as_completed')
        ).side_effect = as_competed

        get_events_for_detection_mock = stack.enter_context(
            mock.patch('api.workflow.get_events_for_detection')
        )

        get_events_for_detection_mock.return_value = success(
            load_fixture('integration/events_for_detection')
        )

        get_events_for_entity_mock = stack.enter_context(
            mock.patch('api.workflow.get_events_for_entity')
        )

        get_events_for_entity_mock.return_value = success(
            load_fixture('integration/events_for_entity')
        )

        expected_events = load_fixture('workflow/events_for_observable')

        get_dhcp_records_by_ip_mock = stack.enter_context(
            mock.patch('api.workflow.get_dhcp_records_by_ip')
        )

        get_dhcp_records_by_ip_mock.return_value = success(
            load_fixture('integration/dhcp_records_by_ip')
        )

        # 2. Act.

        key = 'Chop Suey!'
        observable = load_fixture('observable')

        events, error = get_events_for_observable(key, observable)

        # 3. Assert.

        entity = observable['value']

        get_detections_for_entity_mock.assert_called_once_with(key, entity)

        get_events_for_detection_mock.assert_has_calls([
            mock.call(key, detection['uuid'])
            for detection in detections
        ])

        get_events_for_entity_mock.assert_called_once_with(key, entity)

        # The actual algorithm for building the `event_time_by_ip` argument is
        # quite unwieldy but straightforward at the same time, so let's just
        # ignore it and don't repeat the same code one more time again.
        get_dhcp_records_by_ip_mock.assert_called_once_with(key, mock.ANY)

        assert events == expected_events
        assert error is None
