import tempfile
import os
from pathlib import Path
from typing import Iterable, Union
from shutil import rmtree

from .mock import DictatureTableMock, DictatureBackendMock, Value, ValueMode, ValueSerializer, ValueSerializerMode


class DictatureBackendDirectory(DictatureBackendMock):
    def __init__(self, directory: Union[Path, str], dir_prefix: str = 'db_', item_prefix: str = 'item_') -> None:
        """
        Create a new directory backend
        :param directory: directory to store the data
        :param dir_prefix: prefix for the directories of the tables
        """
        if isinstance(directory, str):
            directory = Path(directory)
        self.__directory = directory
        self.__dir_prefix = dir_prefix
        self.__item_prefix = item_prefix

    def keys(self) -> Iterable[str]:
        for child in self.__directory.iterdir():
            if child.is_dir() and child.name.startswith(self.__dir_prefix):
                # noinspection PyProtectedMember
                yield DictatureTableDirectory._filename_decode(child.name[len(self.__dir_prefix):], suffix='')

    def table(self, name: str) -> 'DictatureTableMock':
        return DictatureTableDirectory(self.__directory, name, self.__dir_prefix, self.__item_prefix)


class DictatureTableDirectory(DictatureTableMock):
    def __init__(self, path_root: Path, name: str, db_prefix: str, prefix: str) -> None:
        self.__path = path_root / (db_prefix + self._filename_encode(name, suffix=''))
        self.__prefix = prefix
        self.__name_serializer = ValueSerializer(mode=ValueSerializerMode.filename_only)
        self.__value_serializer = ValueSerializer(mode=ValueSerializerMode.any_string)

    def keys(self) -> Iterable[str]:
        for child in self.__path.iterdir():
            if child.is_file() and child.name.startswith(self.__prefix) and not child.name.endswith('.tmp'):
                yield self._filename_decode(child.name[len(self.__prefix):])

    def drop(self) -> None:
        rmtree(self.__path)

    def create(self) -> None:
        self.__path.mkdir(parents=True, exist_ok=True)

    def set(self, item: str, value: Value) -> None:
        file_target = self.__item_path(item)

        # Create temporary file for atomic write
        handle, file_target_tmp_path = tempfile.mkstemp(prefix=file_target.name, suffix='.tmp', dir=file_target.parent)
        os.close(handle)
        file_target_tmp = Path(file_target_tmp_path)

        save_data = self.__value_serializer.serialize(value)

        file_target_tmp.write_text(save_data)
        file_target_tmp.rename(file_target)

    def get(self, item: str) -> Value:
        try:
            save_data = self.__item_path(item).read_text()
            return self.__value_serializer.deserialize(save_data)
        except FileNotFoundError:
            raise KeyError(item)

    def delete(self, item: str) -> None:
        if self.__item_path(item).exists():
            self.__item_path(item).unlink()

    def __item_path(self, item: str) -> Path:
        return self.__path / (self.__prefix + self._filename_encode(item))

    @staticmethod
    def _filename_encode(name: str, suffix: str = '.txt') -> str:
        return ValueSerializer(mode=ValueSerializerMode.filename_only).serialize(Value(
            value=name,
            mode=ValueMode.string.value
        )) + suffix

    @staticmethod
    def _filename_decode(name: str, suffix: str = '.txt') -> str:
        if suffix:
            name = name[:-len(suffix)]
        return ValueSerializer(mode=ValueSerializerMode.filename_only).deserialize(name).value
