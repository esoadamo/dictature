"""Backend that wraps a DictatureTable and uses prefixes to simulate multiple tables."""
from typing import Iterable

from .mock import DictatureBackendMock, DictatureTableMock, Value, ValueMode


class DictatureSingleTableBackend(DictatureBackendMock):
    """
    Backend that stores all tables in a single DictatureTable using prefixes.
    
    This allows using any existing DictatureTable as a backend for multiple
    virtual tables, distinguished by key prefixes.
    """

    def __init__(self, table: 'DictatureTable', separator: str = '::') -> None:
        """
        Create a new SingleTableBackend.
        :param table: The underlying DictatureTable to store all data in
        :param separator: String used to separate table name from key (default: '::')
        """
        self.__table = table
        self.__separator = separator

    def keys(self) -> Iterable[str]:
        """Return all virtual table names."""
        seen = set()
        for key in self.__table.keys():
            if self.__separator in key:
                table_name = key.split(self.__separator, 1)[0]
                if table_name not in seen:
                    seen.add(table_name)
                    yield table_name

    def table(self, name: str) -> 'DictatureSingleTableTable':
        return DictatureSingleTableTable(self.__table, name, self.__separator)


class DictatureSingleTableTable(DictatureTableMock):
    """Virtual table within a SingleTableBackend."""
    
    def __init__(self, parent: 'DictatureTable', table_name: str, separator: str) -> None:
        self.__parent = parent
        self.__prefix = table_name + separator

    def keys(self) -> Iterable[str]:
        """Return all keys in this virtual table."""
        for key in self.__parent.keys():
            if key.startswith(self.__prefix):
                yield key[len(self.__prefix):]

    def drop(self) -> None:
        """Delete all keys for this virtual table."""
        # Collect keys first to avoid modifying during iteration
        keys_to_delete = list(self.keys())
        for key in keys_to_delete:
            del self.__parent[self.__prefix + key]

    def create(self) -> None:
        pass  # Already created by the parent

    def set(self, item: str, value: Value) -> None:
        """Set a value for a key in this virtual table."""
        self.__parent[self.__prefix + item] = {'value': value.value, 'mode': value.mode}

    def get(self, item: str) -> Value:
        """Get a value for a key in this virtual table."""
        value = self.__parent[self.__prefix + item]
        return Value(value['value'], ValueMode(value['mode']))

    def delete(self, item: str) -> None:
        """Delete a key from this virtual table."""
        del self.__parent[self.__prefix + item]
