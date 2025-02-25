import json
import pickle
from gzip import compress, decompress
from base64 import b64encode, b64decode
from random import choice
from typing import Optional, Dict, Any, Set, Iterator, Tuple

from .backend import DictatureBackendMock, ValueMode, Value


class Dictature:
    def __init__(self, backend: DictatureBackendMock) -> None:
        self.__db = backend
        self.__db_cache: Dict[str, "DictatureTable"] = {}

    def keys(self) -> Set[str]:
        return set(self.__db.keys())

    def values(self) -> Iterator["DictatureTable"]:
        return map(lambda x: x[1], self.items())

    def items(self) -> Iterator[Tuple[str, "DictatureTable"]]:
        for k in self.keys():
            yield k, self[k]

    def to_dict(self) -> Dict[str, Any]:
        return {k: v.to_dict() for k, v in self.items()}

    def __str__(self):
        return str(self.to_dict())

    def __getitem__(self, item: str) -> "DictatureTable":
        if len(self.__db_cache) > 128:
            del self.__db_cache[choice(list(self.__db_cache.keys()))]
        if item not in self.__db_cache:
            self.__db_cache[item] = DictatureTable(self.__db, item)
        return self.__db_cache[item]

    def __delitem__(self, key: str) -> None:
        self[key].drop()

    def __contains__(self, item: str) -> bool:
        return item in self.keys()

    def __bool__(self) -> bool:
        return not not self.keys()


class DictatureTable:
    def __init__(self, db: DictatureBackendMock, table_name: str):
        self.__db = db
        self.__table = self.__db.table(table_name)
        self.__table_created = False

    def get(self, item: str, default: Optional[Any] = None) -> Any:
        try:
            return self[item]
        except KeyError:
            return default

    def key_exists(self, item: str) -> bool:
        self.__create_table()
        return item in self.keys()

    def keys(self) -> Set[str]:
        self.__create_table()
        return set(self.__table.keys())

    def values(self) -> Iterator[Any]:
        return map(lambda x: x[1], self.items())

    def items(self) -> Iterator[Tuple[str, Any]]:
        for k in self.keys():
            yield k, self[k]

    def drop(self) -> None:
        self.__create_table()
        self.__table.drop()

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in self.items()}

    def __str__(self):
        return str(self.to_dict())

    def __getitem__(self, item: str) -> Any:
        self.__create_table()
        value = self.__table.get(item)
        mode = ValueMode(value.mode)
        match mode:
            case ValueMode.string:
                return value.value
            case ValueMode.json:
                return json.loads(value.value)
            case ValueMode.pickle:
                return pickle.loads(decompress(b64decode(value.value.encode('ascii'))))
        raise ValueError(f"Unknown mode '{value.mode}'")

    def __setitem__(self, key: str, value: Any) -> None:
        self.__create_table()
        value_mode = ValueMode.string

        if type(value) is not str:
            try:
                value = json.dumps(value)
                value_mode = ValueMode.json
            except TypeError:
                value = b64encode(compress(pickle.dumps(value))).decode('ascii')
                value_mode = value_mode.pickle

        self.__table.set(key, Value(value=value, mode=value_mode.value))

    def __delitem__(self, key: str) -> None:
        self.__table.delete(key)

    def __contains__(self, item: str):
        return item in self.keys()

    def __bool__(self) -> bool:
        return not not self.keys()

    def __create_table(self) -> None:
        if self.__table_created:
            return
        self.__table.create()
        self.__table_created = True
