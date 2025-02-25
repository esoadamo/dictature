from typing import Iterable, NamedTuple
from enum import Enum


class ValueMode(Enum):
    string = 0
    json = 1
    pickle = 2


class Value(NamedTuple):
    value: str
    mode: int


class DictatureBackendMock:
    def keys(self) -> Iterable[str]:
        raise NotImplementedError("This method should be implemented by the subclass")

    def table(self, name: str) -> 'DictatureTableMock':
        raise NotImplementedError("This method should be implemented by the subclass")


class DictatureTableMock:
    def keys(self) -> Iterable[str]:
        raise NotImplementedError("This method should be implemented by the subclass")

    def drop(self) -> None:
        raise NotImplementedError("This method should be implemented by the subclass")

    def create(self) -> None:
        raise NotImplementedError("This method should be implemented by the subclass")

    def set(self, item: str, value: Value) -> None:
        raise NotImplementedError("This method should be implemented by the subclass")

    def get(self, item: str) -> Value:
        raise NotImplementedError("This method should be implemented by the subclass")

    def delete(self, item: str) -> None:
        raise NotImplementedError("This method should be implemented by the subclass")
