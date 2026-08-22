import json
import pickle
from gzip import compress, decompress
from base64 import b64encode, b64decode
from pathlib import Path
from random import choice
from typing import Optional, Dict, Any, Set, Iterator, Tuple

from .backend import DictatureBackendMock, ValueMode, Value
from .transformer import MockTransformer, PassthroughTransformer, PipelineTransformer


class Dictature:
    def __init__(
            self,
            backend: DictatureBackendMock,
            name_transformer: MockTransformer = PassthroughTransformer(),
            value_transformer: MockTransformer = PassthroughTransformer(),
            table_name_transformer: Optional[MockTransformer] = None,
            allow_pickle: bool = False,
            allow_invalid_keys: bool = True,
    ) -> None:
        """
        Create a new Dictature object
        :param backend: backend to use
        :param name_transformer: transformer to use for table and key names
        :param value_transformer: transformer to use for values
        :param table_name_transformer: transformer to use for table names, if None, name_transformer is used
        :param allow_pickle: if True, pickle is allowed for values (warning: this may be a security risk if the data is not trusted)
        :param allow_invalid_keys: if True, keys that cannot be decoded are quietly skipped
        """
        self.__backend = backend
        self.__table_cache: Dict[str, "DictatureTable"] = {}
        self.__name_transformer = name_transformer
        self.__value_transformer = value_transformer
        self.__table_name_transformer = table_name_transformer or name_transformer
        self.__cache_size = 4096
        self.__allow_pickle = allow_pickle
        self.__allow_invalid_keys = allow_invalid_keys

    def keys(self) -> Set[str]:
        """
        Return all table names
        :return: all table names
        """
        result = set()
        for key in self.__backend.keys():
            try:
                decoded = self.__table_name_transformer.backward(key)
            except Exception:
                if self.__allow_invalid_keys:
                    continue
                raise
            result.add(decoded)
        return result

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

    def with_compression(self, values: bool = True, names: bool = False, table_names: bool | None = None) -> "Dictature":
        """
        Enable gzip compression on this Dictature instance. Can be applied to values, key names, and/or
        table names independently. Returns self for chaining.

        :param values: compress stored values (default: True)
        :param names: compress stored key names within tables (default: False)
        :param table_names: compress stored table names; if None, mirrors the ``names`` argument
        :return: self
        """
        from .transformer.gzip import GzipTransformer
        table_names = table_names if table_names is not None else names
        if values:
            self.__value_transformer = PipelineTransformer([self.__value_transformer, GzipTransformer()])
        if names:
            self.__name_transformer = PipelineTransformer([self.__name_transformer, GzipTransformer()])
        if table_names:
            self.__table_name_transformer = PipelineTransformer([self.__table_name_transformer, GzipTransformer()])
        return self

    def with_encryption(self, passphrase: str, values: bool = True, names: bool = False,
                        table_names: bool | None = None, static_names: bool | None = None, salt: str | None = None) -> "Dictature":
        """
        Enable AES encryption on this Dictature instance. Requires ``pycryptodome`` (``pip install pycryptodome``).
        Values are encrypted with AES-GCM (non-deterministic, more secure). Key and table names are encrypted
        with AES-ECB (deterministic — required so the same name always maps to the same stored key).
        Returns self for chaining.

        :param passphrase: secret passphrase used for key derivation
        :param values: encrypt stored values (default: True)
        :param names: encrypt stored key names within tables (default: False)
        :param table_names: encrypt stored table names; if None, mirrors the ``names`` argument
        :param static_names: override the AES mode for names/table_names — ``True`` forces ECB (deterministic),
            ``False`` forces GCM (non-deterministic); if None, names use ECB and values use GCM (default)
        :param salt: salt for scrypt key derivation; if None, values use ``'dictature-values'``
            and names use ``'dictature-names'`` so the derived keys differ between the two
        :return: self
        """
        from .transformer.aes import AESTransformer
        table_names = table_names if table_names is not None else names
        salt_values = "dictature-values" if salt is None else salt
        salt_names = "dictature-names" if salt is None else salt
        static_names_values = False if static_names is None else static_names
        static_names_names = True if static_names is None else static_names
        static_names_table_names = True if static_names is None else static_names

        if values:
            self.__value_transformer = PipelineTransformer(
                [self.__value_transformer, AESTransformer(passphrase, static_names_mode=static_names_values, salt=salt_values)]
            )
        if names:
            self.__name_transformer = PipelineTransformer(
                [self.__name_transformer, AESTransformer(passphrase, static_names_mode=static_names_names, salt=salt_names)]
            )
        if table_names:
            self.__table_name_transformer = PipelineTransformer(
                [self.__table_name_transformer, AESTransformer(passphrase, static_names_mode=static_names_table_names, salt=salt_names)]
            )
        return self

    def with_hmac(self, secret: str = 'dictature', values: bool = False, names: bool = True,
                  table_names: bool | None = None) -> "Dictature":
        """
        Enable HMAC integrity checking on this Dictature instance. The HMAC is stored alongside the data;
        reading back a value with a mismatched HMAC raises ``ValueError``. Returns self for chaining.

        :param secret: secret key for the HMAC (default: ``'dictature'``)
        :param values: apply HMAC to stored values (default: False)
        :param names: apply HMAC to stored key names within tables (default: True)
        :param table_names: apply HMAC to stored table names; if None, mirrors the ``names`` argument
        :return: self
        """
        from .transformer.hmac import HmacTransformer
        table_names = table_names if table_names is not None else names
        if values:
            self.__value_transformer = PipelineTransformer([self.__value_transformer, HmacTransformer(secret)])
        if names:
            self.__name_transformer = PipelineTransformer([self.__name_transformer, HmacTransformer(secret)])
        if table_names:
            self.__table_name_transformer = PipelineTransformer(
                [self.__table_name_transformer, HmacTransformer(secret)]
            )
        return self

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
                allow_invalid_keys=self.__allow_invalid_keys,
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

    @classmethod
    def sqlite(cls, path: Path | str, prefix: str = "tb_") -> "Dictature":
        """
        Create a Dictature backed by a local SQLite database.

        :param path: path to the ``.sqlite3`` file, or ``':memory:'`` for an in-memory database
        :param prefix: prefix added to every table name inside the database (default: ``'tb_'``)
        :return: new Dictature instance
        """
        from .backend import DictatureBackendSQLite
        return Dictature(DictatureBackendSQLite(path, prefix=prefix))

    @classmethod
    def directory(cls, directory: Path | str, dir_prefix: str = "db_", item_prefix: str = "item_") -> "Dictature":
        """
        Create a Dictature that stores each table as a sub-directory and each value as a file.

        :param directory: root directory to use for storage
        :param dir_prefix: prefix for table sub-directories (default: ``'db_'``)
        :param item_prefix: prefix for item files inside each table directory (default: ``'item_'``)
        :return: new Dictature instance
        """
        from .backend import DictatureBackendDirectory
        return Dictature(DictatureBackendDirectory(directory, dir_prefix=dir_prefix, item_prefix=item_prefix))

    @classmethod
    def single_table(cls, table: "DictatureTable", separator: str = "::") -> "Dictature":
        """
        Create a Dictature that virtualises multiple tables inside a single existing :class:`DictatureTable`
        by prefixing every key with the virtual table name. Useful when the backend does not support
        multiple physical tables.

        :param table: an existing :class:`DictatureTable` to use as the physical storage
        :param separator: string used to separate the virtual table name from the key (default: ``'::'``)
        :return: new Dictature instance
        """
        from .backend import DictatureSingleTableBackend
        return Dictature(DictatureSingleTableBackend(table, separator=separator))

    @classmethod
    def mysql(cls, host: str, port: int = 3306, user: str = None, password: str = None,
              database: str = None, prefix: str = "tb_", **kwargs) -> "Dictature":
        """
        Create a Dictature backed by a MySQL (or MariaDB) database.
        Requires ``mysql-connector-python`` (``pip install mysql-connector-python``).

        :param host: MySQL server hostname or IP address
        :param port: MySQL server port (default: ``3306``)
        :param user: MySQL username
        :param password: MySQL password
        :param database: MySQL database name
        :param prefix: prefix added to every table name (default: ``'tb_'``)
        :param kwargs: additional keyword arguments forwarded to ``mysql.connector.connect``
        :return: new Dictature instance
        """
        from .backend.mysql import DictatureBackendMySQL
        return Dictature(DictatureBackendMySQL(host, port=port, user=user, password=password,
                                               database=database, prefix=prefix, **kwargs))

    @classmethod
    def s3(cls, bucket_name: str, aws_access_key_id: str = None, aws_secret_access_key: str = None,
           region_name: str = None, endpoint_url: str = None,
           dir_prefix: str = "db_", item_prefix: str = "item_") -> "Dictature":
        """
        Create a Dictature backed by an S3 bucket (or any S3-compatible store such as MinIO).
        Requires ``boto3`` (``pip install boto3``).

        :param bucket_name: name of the S3 bucket
        :param aws_access_key_id: AWS access key ID (uses environment / IAM role when omitted)
        :param aws_secret_access_key: AWS secret access key
        :param region_name: AWS region (e.g. ``'us-east-1'``)
        :param endpoint_url: custom endpoint URL for S3-compatible services (e.g. MinIO)
        :param dir_prefix: prefix for table "directories" inside the bucket (default: ``'db_'``)
        :param item_prefix: prefix for item objects inside each table directory (default: ``'item_'``)
        :return: new Dictature instance
        """
        from .backend.s3 import DictatureBackendS3
        return Dictature(DictatureBackendS3(bucket_name, aws_access_key_id=aws_access_key_id,
                                            aws_secret_access_key=aws_secret_access_key,
                                            region_name=region_name, endpoint_url=endpoint_url,
                                            dir_prefix=dir_prefix, item_prefix=item_prefix))

    @classmethod
    def webdav(cls, hostname: str, login: str = None, password: str = None,
               dir_prefix: str = "db_", item_prefix: str = "item_", **kwargs) -> "Dictature":
        """
        Create a Dictature backed by a WebDAV share.
        Requires ``webdavclient3`` (``pip install webdavclient3``).

        :param hostname: WebDAV server URL (e.g. ``'https://dav.example.com/'``)
        :param login: WebDAV username
        :param password: WebDAV password
        :param dir_prefix: prefix for table directories on the share (default: ``'db_'``)
        :param item_prefix: prefix for item files inside each table directory (default: ``'item_'``)
        :param kwargs: additional options forwarded to the ``webdav3.client.Client`` constructor
        :return: new Dictature instance
        """
        from webdav3.client import Client as WebdavClient
        from .backend.webdav import DictatureBackendWebdav
        options = {"webdav_hostname": hostname, **kwargs}
        if login is not None:
            options["webdav_login"] = login
        if password is not None:
            options["webdav_password"] = password
        return Dictature(DictatureBackendWebdav(WebdavClient(options), dir_prefix=dir_prefix, item_prefix=item_prefix))

    @classmethod
    def confluence(cls, base_url: str, username: str, api_token: str, root_page_id: str,
                   sync_page_content: bool = False) -> "Dictature":
        """
        Create a Dictature backed by Confluence, storing data as Content Properties on child pages.
        Requires ``requests`` (``pip install requests``).

        :param base_url: Confluence base URL (e.g. ``'https://yoursite.atlassian.net/wiki'``)
        :param username: Atlassian account email / username
        :param api_token: Atlassian API token
        :param root_page_id: ID of the Confluence page under which table pages will be created
        :param sync_page_content: if True, also update the page body with a table of all properties (slower)
        :return: new Dictature instance
        """
        from .backend.confluence import DictatureBackendConfluence
        return Dictature(DictatureBackendConfluence(base_url, username, api_token, root_page_id,
                                                    sync_page_content=sync_page_content))

    @classmethod
    def baserow(cls, token: str, table_id: int, base_url: str = "https://api.baserow.io") -> "Dictature":
        """
        Create a Dictature backed by a single Baserow table.
        Requires ``requests`` (``pip install requests``).
        The Baserow table must contain the columns ``table``, ``key``, ``value``, and ``mode``.

        :param token: Baserow API token
        :param table_id: numeric ID of the Baserow table
        :param base_url: Baserow API base URL (default: ``'https://api.baserow.io'``)
        :return: new Dictature instance
        """
        from .backend.baserow import DictatureBackendBaserowSingleTable
        return Dictature(DictatureBackendBaserowSingleTable(token, table_id, base_url=base_url))

    @classmethod
    def misp(cls, url: str, key: str, ssl: bool = True,
             tag_name: str = "storage:dictature", prefix: str = "Dictature storage: ") -> "Dictature":
        """
        Create a Dictature backed by a MISP instance, storing each table as a tagged MISP event.
        Requires ``pymisp`` (``pip install pymisp``).

        :param url: MISP instance URL (e.g. ``'https://misp.example.com'``)
        :param key: MISP API key / automation key
        :param ssl: whether to verify the server's SSL certificate (default: ``True``)
        :param tag_name: MISP tag applied to all storage events (default: ``'storage:dictature'``)
        :param prefix: prefix added to MISP event names/titles (default: ``'Dictature storage: '``)
        :return: new Dictature instance
        """
        from pymisp import PyMISP
        from .backend.misp import DictatureBackendMISP
        return Dictature(DictatureBackendMISP(PyMISP(url, key, ssl=ssl), tag_name=tag_name, prefix=prefix))


class DictatureTable:
    def __init__(
            self,
            backend: DictatureBackendMock,
            table_name: str,
            name_transformer: MockTransformer = PassthroughTransformer(),
            value_transformer: MockTransformer = PassthroughTransformer(),
            table_name_transformer: Optional[MockTransformer] = None,
            allow_pickle: bool = False,
            allow_invalid_keys: bool = True,
    ):
        """
        Create a new DictatureTable object
        :param backend: backend to use
        :param table_name: name of the table
        :param name_transformer:  transformer to use for key names
        :param value_transformer: transformer to use for values
        :param allow_pickle: if True, pickle is allowed for values (warning: this may be a security risk if the data is not trusted)
        :param allow_invalid_keys: if True, keys that cannot be decoded are quietly skipped
        """
        self.__backend = backend
        self.__name_transformer = name_transformer
        self.__value_transformer = value_transformer
        self.__table_name_transformer = table_name_transformer or name_transformer
        self.__table = self.__backend.table(self.__table_key(table_name))
        self.__table_created = False
        self.__allow_pickle = allow_pickle
        self.__allow_invalid_keys = allow_invalid_keys

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
        result = set()
        for key in self.__table.keys():
            try:
                decoded = self.__name_transformer.backward(key)
            except Exception:
                if self.__allow_invalid_keys:
                    continue
                raise
            result.add(decoded)
        return result

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
