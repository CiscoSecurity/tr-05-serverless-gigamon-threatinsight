from collections import defaultdict


class Bundle:

    def __init__(self):
        self._entities_by_type = defaultdict(list)

    def add(self, entity):
        # Pluralize the type of an entity to make TR accept it.
        entity_type = entity['type'] + 's'
        self._entities_by_type[entity_type].append(entity)

    @staticmethod
    def _format_docs(docs):
        return {'count': len(docs), 'docs': docs}

    def json(self):
        return {
            entity_type: self._format_docs(entities)
            for entity_type, entities in self._entities_by_type.items()
        }
