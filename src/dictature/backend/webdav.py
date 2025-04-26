import io
import posixpath
from typing import Iterable

try:
    from webdav3.client import Client as WebdavClient
    from webdav3.exceptions import (
        WebDavException,
        RemoteResourceNotFound,
        RemoteParentNotFound,
        MethodNotSupported,
    )
except ImportError:
    raise ImportError('Requires: pip install webdavclient3')

from .mock import DictatureTableMock, DictatureBackendMock, Value, ValueMode, ValueSerializer, ValueSerializerMode


class DictatureBackendWebdav(DictatureBackendMock):
    def __init__(
            self,
            client: WebdavClient,
            dir_prefix: str = 'db_',
            item_prefix: str = 'item_'
    ) -> None:
        self.__client = client
        self.__dir_prefix = dir_prefix
        self.__item_prefix = item_prefix

    def keys(self) -> Iterable[str]:
        try:
            resources = self.__client.list(get_info=True)

            for resource_info in resources:
                name = posixpath.basename(posixpath.dirname(resource_info.get('path')))
                is_dir = resource_info.get('isdir', False)

                if not name:
                    continue

                if is_dir and name.startswith(self.__dir_prefix):
                    table_name_encoded = name[len(self.__dir_prefix):]
                    # noinspection PyProtectedMember
                    yield DictatureTableWebdav._filename_decode(table_name_encoded, suffix='')
        except RemoteResourceNotFound:
            pass

    def table(self, name: str) -> 'DictatureTableMock':
        return DictatureTableWebdav(self.__client, name, self.__dir_prefix, self.__item_prefix)


class DictatureTableWebdav(DictatureTableMock):
    def __init__(self, client: WebdavClient, name: str, db_prefix: str, prefix: str) -> None:
        self.__client = client
        self.__encoded_name = self._filename_encode(name, suffix='')
        self.__path = posixpath.join(db_prefix + self.__encoded_name)
        self.__prefix = prefix
        self.__name_serializer = ValueSerializer(mode=ValueSerializerMode.filename_only)
        self.__value_serializer = ValueSerializer(mode=ValueSerializerMode.any_string)

    def keys(self) -> Iterable[str]:
        try:
            resources = self.__client.list(self.__path, get_info=True)

            for resource_info in resources:
                name = posixpath.basename(resource_info.get('path'))
                is_dir = resource_info.get('isdir', False)

                if not name:
                    continue

                if not is_dir and name.startswith(self.__prefix):
                    item_name_encoded = name[len(self.__prefix):]
                    yield self._filename_decode(item_name_encoded, suffix='.txt')

        except RemoteResourceNotFound:
            pass

    def drop(self) -> None:
        try:
            self.__client.clean(self.__path)
        except RemoteResourceNotFound:
            pass

    def create(self) -> None:
        try:
            if not self.__client.check(self.__path):
                self.__client.mkdir(self.__path)
        except MethodNotSupported as e:
            if not self.__client.check(self.__path):
                raise e

    def set(self, item: str, value: Value) -> None:
        item_path = self.__item_path(item)
        self.create()

        save_data: str = self.__value_serializer.serialize(value)
        data_bytes = save_data.encode('utf-8')

        with io.BytesIO(data_bytes) as buffer:
            self.__client.upload_to(buffer, item_path)

    def get(self, item: str) -> Value:
        item_path = self.__item_path(item)
        buffer = io.BytesIO()
        try:
            self.__client.download_from(buffer, item_path)
            buffer.seek(0)
            save_data = buffer.read().decode('utf-8')
        except RemoteResourceNotFound:
            raise KeyError(item)
        return self.__value_serializer.deserialize(save_data)

    def delete(self, item: str) -> None:
        """
        Deletes the file corresponding to the item. No error if not found.
        Raises WebDavException for other deletion errors.
        """
        item_path = self.__item_path(item)
        try:
            self.__client.clean(item_path)
        except RemoteResourceNotFound:
            pass

    def __item_path(self, item: str) -> str:
        encoded_item_name = self.__prefix + self._filename_encode(item, suffix='.txt')
        full_path = posixpath.join(self.__path, encoded_item_name)
        return full_path

    @staticmethod
    def _filename_encode(name: str, suffix: str = '.txt') -> str:
        return ValueSerializer(mode=ValueSerializerMode.filename_only).serialize(Value(
            value=name,
            mode=ValueMode.string.value
        )) + suffix

    @staticmethod
    def _filename_decode(name: str, suffix: str = '.txt') -> str:
        if suffix and name.endswith(suffix):
            name = name[:-len(suffix)]
        return ValueSerializer(mode=ValueSerializerMode.filename_only).deserialize(name).value
