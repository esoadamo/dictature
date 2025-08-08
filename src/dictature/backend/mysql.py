try:
    import mysql.connector
except ImportError:
    raise ImportError('Requires: pip install mysql-connector-python') from None
from typing import Iterable

from .mock import DictatureBackendMock, DictatureTableMock, Value


class DictatureBackendMySQL(DictatureBackendMock):
    def __init__(self, host: str, port: int = 3306, user: str = None, password: str = None,
                 database: str = None, prefix: str = 'tb_', **kwargs) -> None:
        """
        Create a new MySQL backend
        :param host: MySQL server host
        :param port: MySQL server port (default: 3306)
        :param user: MySQL username
        :param password: MySQL password
        :param database: MySQL database name
        :param kwargs: Additional connection parameters
        """
        self.__connection_params = {
            'host': host,
            'port': port,
            'user': user,
            'password': password,
            'database': database,
            **kwargs
        }

        # Remove None values from connection params
        self.__connection_params = {k: v for k, v in self.__connection_params.items() if v is not None}

        self.__connection = mysql.connector.connect(**self.__connection_params)
        self.__cursor = self.__connection.cursor()
        self.__prefix = prefix.replace('`', '').replace("'", '')

    def keys(self) -> Iterable[str]:
        # noinspection SqlResolve
        tables = self._execute(f"SELECT table_name FROM information_schema.tables WHERE table_schema = %s AND table_name LIKE '{self.__prefix}%'", (self.__connection_params['database'],))
        return {table[0][len(self.__prefix):] for table in tables}

    def table(self, name: str) -> 'DictatureTableMock':
        return DictatureTableMySQL(self, name, self.__prefix)

    def _execute(self, query: str, data: tuple = ()) -> list:
        self.__cursor.execute(query, data)
        return self.__cursor.fetchall()

    def _commit(self) -> None:
        self.__connection.commit()

    def __del__(self):
        if hasattr(self, '_DictatureBackendMySQL__connection'):
            self.__connection.close()


class DictatureTableMySQL(DictatureTableMock):
    def __init__(self, parent: "DictatureBackendMySQL", name: str, prefix: str) -> None:
        self.__parent = parent
        # MySQL table names don't need backticks for simple names, but we'll use them for consistency
        self.__table = f"`{prefix}{name.replace('`', '')}`"

    def keys(self) -> Iterable[str]:
        # noinspection PyProtectedMember
        result = self.__parent._execute(f"SELECT `key` FROM {self.__table}")
        return set(map(lambda x: x[0], result))

    def drop(self) -> None:
        # noinspection PyProtectedMember
        self.__parent._execute(f"DROP TABLE {self.__table}")

    def key_exists(self, item: str) -> bool:
        # noinspection PyProtectedMember
        result = self.__parent._execute(f"SELECT `value` FROM {self.__table} WHERE `key`=%s", (item,))
        return len(result) > 0

    def create(self) -> None:
        # noinspection PyProtectedMember
        self.__parent._execute(f"""
        CREATE TABLE IF NOT EXISTS {self.__table} (
        `key` VARCHAR(700) NOT NULL UNIQUE,
        `value` TEXT,
        `type` INT NOT NULL DEFAULT 0,
        PRIMARY KEY (`key`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)

    def set(self, item: str, value: Value) -> None:
        if self.key_exists(item):
            # noinspection PyProtectedMember
            self.__parent._execute(f"""
            UPDATE {self.__table} SET `value`=%s, `type`=%s WHERE `key`=%s
            """, (value.value, value.mode, item))
        else:
            # noinspection PyProtectedMember
            self.__parent._execute(
                f"INSERT INTO {self.__table} (`key`, `value`, `type`) VALUES (%s, %s, %s)",
                (item, value.value, value.mode)
            )
        # noinspection PyProtectedMember
        self.__parent._commit()

    def get(self, item: str) -> Value:
        # noinspection PyProtectedMember
        r = self.__parent._execute(f"SELECT `value`, `type` FROM {self.__table} WHERE `key`=%s", (item,))
        if r:
            value: str = r[0][0]
            type_value: int = r[0][1]
            return Value(value=value, mode=type_value)
        raise KeyError(item)

    def delete(self, item: str) -> None:
        # noinspection PyProtectedMember
        self.__parent._execute(
            f"DELETE FROM {self.__table} WHERE `key`=%s", (item,)
        )
        # noinspection PyProtectedMember
        self.__parent._commit()
