import json
import os


def headers(jwt):
    return {'Authorization': f'Bearer {jwt}'}


def fixture_for(file_name):
    if not file_name.endswith('.json'):
        file_name += '.json'

    file_path = os.path.join(
        os.path.dirname(__file__),
        'fixtures',
        file_name,
    )

    with open(file_path) as file_obj:
        return json.load(file_obj)
