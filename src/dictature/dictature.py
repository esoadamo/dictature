import json
import pickle
from gzip import compress, decompress
from base64 import b64encode, b64decode
from random import choice
from typing import Optional, Dict, Any, Set, Iterator, Tuple

from .backend import DictatureBackendMock, ValueMode, Value
from .transformer import MockTransformer, PassthroughTransformer


class Dictature:
    def __init__(
            self,
            backend: DictatureBackendMock,
            name_transformer: MockTransformer = PassthroughTransformer(),
            value_transformer: MockTransformer = PassthroughTransformer(),
            table_name_transformer: Optional[MockTransformer] = None,
            allow_pickle: bool = True,
    ) -> None:
        """
        Create a new Dictature object
        :param backend: backend to use
        :param name_transformer: transformer to use for table and key names
        :param value_transformer: transformer to use for values
        :param table_name_transformer: transformer to use for table names, if None, name_transformer is used
        :param allow_pickle: if True, pickle is allowed for values (warning: this may be a security risk if the data is not trusted)
        """
        self.__backend = backend
        self.__table_cache: Dict[str, "DictatureTable"] = {}
        self.__name_transformer = name_transformer
        self.__value_transformer = value_transformer
        self.__table_name_transformer = table_name_transformer or name_transformer
        self.__cache_size = 4096
        self.__allow_pickle = allow_pickle

    def keys(self) -> Set[str]:
        """
        Return all table names
        :return: all table names
        """
        return set(map(self.__table_name_transformer.backward, self.__backend.keys()))

    def values(self) -> Iterator["DictatureTable"]:
        """
        Return all tables
        :return: all tables
        """
        return map(lambda x: x[1], self.items())

    def items(self) -> Iterator[Tuple[str, "DictatureTable"]]:
        """
        Return all tables with their instances
        :return: all tables with their instances
        """
        for k in self.keys():
            yield k, self[k]

    def to_dict(self) -> Dict[str, Any]:
        """
        Return all tables as a dictionary
        :return: all tables as a dictionary
        """
        return {k: v.to_dict() for k, v in self.items()}

    def __str__(self):
        """
        Return all tables as a string
        :return: all tables as a string
        """
        return str(self.to_dict())

    def __getitem__(self, item: str) -> "DictatureTable":
        """
        Get a table by name
        :param item: name of the table
        :return: table instance
        """
        if len(self.__table_cache) > self.__cache_size:
            del self.__table_cache[choice(list(self.__table_cache.keys()))]
        if item not in self.__table_cache:
            self.__table_cache[item] = DictatureTable(
                self.__backend,
                item,
                name_transformer=self.__name_transformer,
                value_transformer=self.__value_transformer,
                table_name_transformer=self.__table_name_transformer,
                allow_pickle=self.__allow_pickle,
            )
        return self.__table_cache[item]

    def __delitem__(self, key: str) -> None:
        """
        Delete a table
        :param key: name of the table
        :return: None
        """
        self[key].drop()

    def __contains__(self, item: str) -> bool:
        """
        Check if a table exists
        :param item: name of the table
        :return: True if the table exists, False otherwise
        """
        return item in self.keys()

    def __bool__(self) -> bool:
        """
        Check if there are any tables
        :return: True if there are tables, False otherwise
        """
        return not not self.keys()


class DictatureTable:
    def __init__(
            self,
            backend: DictatureBackendMock,
            table_name: str,
            name_transformer: MockTransformer = PassthroughTransformer(),
            value_transformer: MockTransformer = PassthroughTransformer(),
            table_name_transformer: Optional[MockTransformer] = None,
            allow_pickle: bool = True
    ):
        """
        Create a new DictatureTable object
        :param backend: backend to use
        :param table_name: name of the table
        :param name_transformer:  transformer to use for key names
        :param value_transformer: transformer to use for values
        :param allow_pickle: if True, pickle is allowed for values (warning: this may be a security risk if the data is not trusted)
        """
        self.__backend = backend
        self.__name_transformer = name_transformer
        self.__value_transformer = value_transformer
        self.__table_name_transformer = table_name_transformer or name_transformer
        self.__table = self.__backend.table(self.__table_key(table_name))
        self.__table_created = False
        self.__allow_pickle = allow_pickle

    def get(self, item: str, default: Optional[Any] = None) -> Any:
        """
        Get a value from the table
        :param item: key to get
        :param default: default value to return if the key does not exist
        :return: value or default
        """
        try:
            return self[item]
        except KeyError:
            return default

    def key_exists(self, item: str) -> bool:
        """
        Check if a key exists
        :param item: key to check
        :return: True if the key exists, False otherwise
        """
        self.__create_table()
        return item in self.keys()

    def keys(self) -> Set[str]:
        """
        Return all keys in the table
        :return: all keys in the table
        """
        self.__create_table()
        return set(map(self.__name_transformer.backward, self.__table.keys()))

    def values(self) -> Iterator[Any]:
        """
        Return all values in the table
        :return: all values in the table
        """
        return map(lambda x: x[1], self.items())

    def items(self) -> Iterator[Tuple[str, Any]]:
        """
        Return all items in the table
        :return: all items in the table
        """
        for k in self.keys():
            yield k, self[k]

    def drop(self) -> None:
        """
        Delete the table
        :return: None
        """
        self.__create_table()
        self.__table.drop()

    def to_dict(self) -> Dict[str, Any]:
        """
        Return all items as a dictionary
        :return: all items as a dictionary
        """
        return {k: v for k, v in self.items()}

    def __str__(self):
        """
        Return all items as a string
        :return: all items as a string
        """
        return str(self.to_dict())

    def __getitem__(self, item: str) -> Any:
        """
        Get a value from the table
        :param item: key to get
        :return: value
        """
        self.__create_table()
        saved_value = self.__table.get(self.__item_key(item))
        mode = ValueMode(saved_value.mode)
        value = self.__value_transformer.backward(saved_value.value)
        if mode == ValueMode.string:
            return value
        elif mode == ValueMode.json:
            return json.loads(value)
        elif mode == ValueMode.pickle:
            if not self.__allow_pickle:
                raise ValueError("Pickle is not allowed")
            return pickle.loads(decompress(b64decode(value.encode('ascii'))))
        raise ValueError(f"Unknown mode '{mode}'")

    def __setitem__(self, key: str, value: Any) -> None:
        """
        Set a value in the table
        :param key: key to set
        :param value: value to set
        :return: None
        """
        self.__create_table()
        value_mode: int = ValueMode.string.value

        if type(value) is not str:
            try:
                value = json.dumps(value)
                value_mode = ValueMode.json.value
            except TypeError:
                if not self.__allow_pickle:
                    raise ValueError("Pickle is not allowed")
                value = b64encode(compress(pickle.dumps(value))).decode('ascii')
                value_mode = ValueMode.pickle.value

        key = self.__item_key(key)
        value = self.__value_transformer.forward(value)
        self.__table.set(key, Value(value=value, mode=value_mode))

    def __delitem__(self, key: str) -> None:
        """
        Delete a key from the table
        :param key: key to delete
        :return: None
        """
        self.__table.delete(self.__item_key(key))

    def __contains__(self, item: str):
        """
        Check if a key exists
        :param item: key to check
        :return: True if the key exists, False otherwise
        """
        return item in self.keys()

    def __bool__(self) -> bool:
        """
        Check if there are any items in the table
        :return: True if there are items, False otherwise
        """
        return not not self.keys()

    def __create_table(self) -> None:
        """
        Create the table if it does not exist
        :return: None
        """
        if self.__table_created:
            return
        self.__table.create()
        self.__table_created = True

    def __item_key(self, item: str) -> str:
        """
        Transform the key for storage
        :param item: key to transform
        :return: transformed key
        """
        if not self.__name_transformer.static:
            for key in self.__table.keys():
                if self.__name_transformer.backward(key) == item:
                    return key
        return self.__name_transformer.forward(item)

    def __table_key(self, table_name: str) -> str:
        """
        Transform the table name for storage
        :param table_name: table name to transform
        :return: transformed table name
        """
        if not self.__table_name_transformer.static:
            for key in self.__backend.keys():
                if self.__table_name_transformer.backward(key) == table_name:
                    return key
        return self.__table_name_transformer.forward(table_name)
