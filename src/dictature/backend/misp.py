from json import dumps, loads
from re import sub
from typing import Iterable, Optional

from .mock import DictatureTableMock, DictatureBackendMock, Value, ValueMode

try:
    from pymisp import PyMISP, MISPEvent, MISPAttribute
except ImportError as e:
    raise ImportError("Please install the 'pymisp' package to use the 'DictatureBackendMISP' backend.") from e


class DictatureBackendMISP(DictatureBackendMock):
    def __init__(self, misp: PyMISP, tag_name: str = 'storage:dictature', prefix: str = 'Dictature storage: ') -> None:
        """
        Create a new MISP backend
        :param misp: PyMISP instance
        :param tag_name: tag name to use for the tables
        :param prefix: prefix for the event names
        """
        self.__misp = misp
        self.__tag_name = tag_name
        self.__prefix = prefix

    def keys(self) -> Iterable[str]:
        for event in self.__misp.search(tags=[self.__tag_name], pythonify=True):
            name = event.info
            if not name.startswith(self.__prefix):
                continue
            yield name[len(self.__prefix):]

    def table(self, name: str) -> 'DictatureTableMock':
        return DictatureTableMISP(self.__misp, self.__prefix + name, self.__tag_name)


class DictatureTableMISP(DictatureTableMock):
    def __init__(self, misp: PyMISP, event_description: str, tag: str) -> None:
        self.__misp = misp
        self.__event_description = event_description
        self.__tag = tag
        self.__event: Optional[MISPEvent] = None

    def keys(self) -> Iterable[str]:
        for attribute in self.__event_attributes():
            yield attribute.value

    def drop(self) -> None:
        self.__misp.delete_event(self.__get_event())

    def create(self) -> None:
        self.__get_event()

    def set(self, item: str, value: Value) -> None:
        save_as_json = value.mode != ValueMode.string.value or value.value.startswith('{')
        save_data = dumps({'value': value.value, 'mode': value.mode}, indent=1) if save_as_json else value.value

        for attribute in self.__event_attributes():
            if attribute.value == item:
                attribute.value = item
                attribute.comment = save_data
                self.__misp.update_attribute(attribute)
                break
        else:
            attribute = MISPAttribute()
            attribute.value = item
            attribute.comment = save_data
            attribute.type = 'comment'
            attribute.to_ids = False
            attribute.disable_correlation = True
            self.__misp.add_attribute(self.__get_event(), attribute)
            self.__get_event().attributes.append(attribute)

    def get(self, item: str) -> Value:
        for attribute in self.__event_attributes():
            if attribute.value == item:
                if attribute.comment.startswith('{'):
                    data = loads(attribute.comment)
                    return Value(data['value'], data['mode'])
                return Value(attribute.comment, ValueMode.string.value)
        raise KeyError(item)

    def delete(self, item: str) -> None:
        for attribute in self.__event_attributes():
            if attribute.value == item:
                # First update the attribute as deletion is not recognized immediately
                attribute.type = 'other'
                self.__misp.update_attribute(attribute)
                self.__misp.delete_attribute(attribute)
                break

    def __get_event(self) -> MISPEvent:
        if self.__event is None:
            for event in self.__misp.search(tags=[self.__tag], eventinfo=self.__event_description, pythonify=True):
                if event.info == self.__event_description:
                    self.__event = event
                    break
            else:
                event = MISPEvent()
                event.info = self.__event_description
                event.distribution = 0
                event.threat_level_id = 4
                event.analysis = 0
                event.add_tag(self.__tag)
                self.__misp.add_event(event)
                self.__event = event
        return self.__event

    def __event_attributes(self) -> Iterable[MISPAttribute]:
        for attribute in self.__get_event().attributes:
            if attribute.type != 'comment' or (hasattr(attribute, 'deleted') and attribute.deleted):
                continue
            yield attribute

    @staticmethod
    def _record_encode(name: str, suffix: str = '.txt') -> str:
        if name == sub(r'[^\w_. -]', '_', name):
            return f"d_{name}{suffix}"
        name = name.encode('utf-8').hex()
        return f'e_{name}{suffix}'

    @staticmethod
    def _record_decode(name: str, suffix: str = '.txt') -> str:
        encoded_name = name[2:-len(suffix) if suffix else len(name)]
        if name.startswith('d_'):
            return encoded_name
        return bytes.fromhex(encoded_name).decode('utf-8')
