import sqlite3
from pathlib import Path
from typing import Iterable, Union, Optional

from .mock import DictatureBackendMock, DictatureTableMock, Value, ValueMode


class DictatureBackendSQLite(DictatureBackendMock):
    def __init__(self, file: Union[str, Path], prefix: str = 'tb_') -> None:
        """
        Create a new SQLite backend
        :param file: file to store the database
        :param prefix: prefix for the tables (default: 'tb_')
        """
        if isinstance(file, str):
            file = Path(file)
        self.__file = file
        self.__connection = sqlite3.connect(
            f"{self.__file.absolute()}",
            check_same_thread=False if sqlite3.threadsafety >= 3 else True
        )
        self.__cursor = self.__connection.cursor()
        self.__prefix = prefix.replace("'", "").replace('`', '')

    def keys(self) -> Iterable[str]:
        tables = self._execute(f"SELECT tbl_name FROM sqlite_master WHERE type='table' AND tbl_name LIKE '{self.__prefix}%'")
        return {table[0][len(self.__prefix):] for table in tables}

    def table(self, name: str) -> 'DictatureTableMock':
        return DictatureTableSQLite(self, name, self.__prefix)

    def _execute(self, query: str, data: tuple = ()) -> list:
        return list(self.__cursor.execute(query, data))

    def _commit(self) -> None:
        self.__connection.commit()

    def __del__(self):
        self.__connection.close()


class DictatureTableSQLite(DictatureTableMock):
    def __init__(self, parent: "DictatureBackendSQLite", name: str, prefix: str) -> None:
        self.__parent = parent
        self.__supports_jsonization: Optional[bool] = None
        self.__table = "`%s`" % (prefix + name).replace('`', '``')

    def keys(self) -> Iterable[str]:
        # noinspection PyProtectedMember
        return set(map(lambda x: x[0], self.__parent._execute(f"SELECT key FROM {self.__table}")))

    def drop(self) -> None:
        # noinspection PyProtectedMember
        self.__parent._execute(f"DROP TABLE {self.__table}")

    def key_exists(self, item: str) -> bool:
        # noinspection PyProtectedMember
        return not not self.__parent._execute(f"SELECT value FROM {self.__table} WHERE key=?", (item,))

    def create(self) -> None:
        # noinspection PyProtectedMember
        self.__parent._execute(f"""
        CREATE TABLE IF NOT EXISTS {self.__table} (
        `key`	TEXT NOT NULL UNIQUE,
        `value`	TEXT
        );
        """)

    def set(self, item: str, value: Value) -> None:
        if value.mode != ValueMode.string:
            self.__support_jsonization()

        if self.key_exists(item):
            if self.__test_supports_jsonization():
                # noinspection PyProtectedMember
                self.__parent._execute(f"""
                UPDATE {self.__table} SET value=?, jsonized=? WHERE key=?
                """, (value.value, value.mode, item))
            else:
                # noinspection PyProtectedMember
                self.__parent._execute(f"UPDATE {self.__table} SET value=? WHERE key=?", (value.value, item))
        else:
            if self.__test_supports_jsonization():
                # noinspection PyProtectedMember
                self.__parent._execute(
                    f"INSERT INTO {self.__table} (`key`,`value`,`jsonized`) VALUES (?,?,?);",
                    (item, value.value, value.mode)
                )
            else:
                # noinspection PyProtectedMember
                self.__parent._execute(
                    f"INSERT INTO {self.__table} (`key`,`value`) VALUES (?,?);", (item, value.value)
                )
        # noinspection PyProtectedMember
        self.__parent._commit()

    def get(self, item: str) -> Value:
        if self.__test_supports_jsonization():
            cmd = f"SELECT value, jsonized FROM {self.__table} WHERE key=?"
        else:
            cmd = f"SELECT value FROM {self.__table} WHERE key=?"

        # noinspection PyProtectedMember
        r = self.__parent._execute(cmd, (item,))
        if r:
            value: str = r[0][0]

            if self.__supports_jsonization:
                jsonized_state: int = r[0][1]
            else:
                jsonized_state = ValueMode.string.value

            return Value(value=value, mode=jsonized_state)
        raise KeyError(item)

    def delete(self, item: str) -> None:
        # noinspection PyProtectedMember
        self.__parent._execute(
            f"DELETE FROM {self.__table} WHERE `key`=?;", (item,)
        )
        # noinspection PyProtectedMember
        self.__parent._commit()

    def __test_supports_jsonization(self) -> bool:
        if self.__supports_jsonization is not None:
            return self.__supports_jsonization
        # noinspection PyProtectedMember
        for _, column_name, _, _, _, _ in self.__parent._execute(f"PRAGMA table_info({self.__table})"):
            if column_name == 'jsonized':
                self.__supports_jsonization = True
                return True
        self.__supports_jsonization = False
        return False

    def __support_jsonization(self) -> None:
        if self.__supports_jsonization or self.__test_supports_jsonization():
            return
        # noinspection PyProtectedMember
        self.__parent._execute(f"""
        ALTER TABLE {self.__table} ADD COLUMN jsonized INTEGER NOT NULL DEFAULT 0
        """)
        self.__supports_jsonization = True