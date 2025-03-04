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
        """
        Return all table names
        :return: all table names
        """
        raise NotImplementedError("This method should be implemented by the subclass")

    def table(self, name: str) -> 'DictatureTableMock':
        """
        Create a table object based on the name
        :param name: name of the table
        :return: table object
        """
        raise NotImplementedError("This method should be implemented by the subclass")


class DictatureTableMock:
    def keys(self) -> Iterable[str]:
        """
        Return all keys in the table
        :return: all keys in the table
        """
        raise NotImplementedError("This method should be implemented by the subclass")

    def drop(self) -> None:
        """
        Delete the table
        :return: None
        """
        raise NotImplementedError("This method should be implemented by the subclass")

    def create(self) -> None:
        """
        Create the table in the backend
        :return: None
        """
        raise NotImplementedError("This method should be implemented by the subclass")

    def set(self, item: str, value: Value) -> None:
        """
        Set a value in the table
        :param item: key to set
        :param value: value to set
        :return: None
        """
        raise NotImplementedError("This method should be implemented by the subclass")

    def get(self, item: str) -> Value:
        """
        Get a value from the table
        :param item: key to get
        :return: value
        :raises KeyError: if the key does not exist
        """
        raise NotImplementedError("This method should be implemented by the subclass")

    def delete(self, item: str) -> None:
        """
        Delete a value from the table
        :param item: key to delete
        :return: None
        """
        raise NotImplementedError("This method should be implemented by the subclass")
