from re import sub
from json import dumps, loads
from pathlib import Path
from typing import Iterable, Union
from shutil import rmtree

from .mock import DictatureTableMock, DictatureBackendMock, Value, ValueMode


class DictatureBackendDirectory(DictatureBackendMock):
    def __init__(self, directory: Union[Path, str], dir_prefix: str = 'db_') -> None:
        if isinstance(directory, str):
            directory = Path(directory)
        self.__directory = directory
        self.__dir_prefix = dir_prefix

    def keys(self) -> Iterable[str]:
        for child in self.__directory.iterdir():
            if child.is_dir() and child.name.startswith(self.__dir_prefix):
                yield child.name[len(self.__dir_prefix):]

    def table(self, name: str) -> 'DictatureTableMock':
        return DictatureTableDirectory(self.__directory, name, self.__dir_prefix)


class DictatureTableDirectory(DictatureTableMock):
    def __init__(self, path_root: Path, name: str, db_prefix: str, prefix: str = 'item_') -> None:
        self.__path = path_root / (db_prefix + self.__filename_encode(name, suffix=''))
        self.__prefix = prefix

    def keys(self) -> Iterable[str]:
        for child in self.__path.iterdir():
            if child.is_file() and child.name.startswith(self.__prefix) and not child.name.endswith('.tmp'):
                yield self.__filename_decode(child.name[len(self.__prefix):])

    def drop(self) -> None:
        rmtree(self.__path)

    def create(self) -> None:
        self.__path.mkdir(parents=True, exist_ok=True)

    def set(self, item: str, value: Value) -> None:
        file_target = self.__item_path(item)
        file_target_tmp = file_target.with_suffix('.tmp')

        save_as_json = value.mode != ValueMode.string.value or value.value.startswith('{')
        save_data = dumps({'value': value.value, 'mode': value.mode}, indent=1) if save_as_json else value.value

        file_target_tmp.write_text(save_data)
        file_target_tmp.rename(file_target)

    def get(self, item: str) -> Value:
        try:
            save_data = self.__item_path(item).read_text()
            if save_data.startswith('{'):
                data = loads(save_data)
                return Value(data['value'], data['mode'])
            return Value(save_data, ValueMode.string.value)
        except FileNotFoundError:
            raise KeyError(item)

    def delete(self, item: str) -> None:
        if self.__item_path(item).exists():
            self.__item_path(item).unlink()

    def __item_path(self, item: str) -> Path:
        return self.__path / (self.__prefix + self.__filename_encode(item))

    @staticmethod
    def __filename_encode(name: str, suffix: str = '.txt') -> str:
        if name == sub(r'[^\w_. -]', '_', name):
            return f"d_{name}{suffix}"
        return f'e_{name.encode('utf-8').hex()}{suffix}'

    @staticmethod
    def __filename_decode(name: str) -> str:
        if name.startswith('d_'):
            return name[2:-5]
        return bytes.fromhex(name[2:-5]).decode('utf-8')
