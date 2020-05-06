import json
import os


def headers(jwt):
    return {'Authorization': f'Bearer {jwt}'}


def load_fixture(path):
    """Load a JSON fixture given a relative path to it."""

    if not path.endswith('.json'):
        path += '.json'

    # Build the absolute path to the fixture.
    path = os.path.join(
        os.path.dirname(__file__),
        'fixtures',
        path,
    )

    with open(path) as file:
        return json.load(file)
