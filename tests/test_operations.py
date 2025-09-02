import unittest
from itertools import product
from typing import NamedTuple, Optional
from tempfile import mkdtemp, mktemp
from base64 import b64decode, b64encode

from parameterized import parameterized

from src.dictature import Dictature
from src.dictature.backend.mock import DictatureBackendMock
from src.dictature.backend.sqlite import DictatureBackendSQLite
from src.dictature.backend.directory import DictatureBackendDirectory
from src.dictature.transformer import PassthroughTransformer, PipelineTransformer
from src.dictature.transformer.mock import MockTransformer
from src.dictature.transformer.aes import AESTransformer
from src.dictature.transformer.hmac import HmacTransformer
from src.dictature.transformer.gzip import GzipTransformer


BACKENDS = [
    DictatureBackendDirectory(mkdtemp(prefix='dictature')),
    DictatureBackendSQLite(mktemp(prefix='dictature', suffix='.sqlite3')),
]

TRANSFORMERS = [
    PassthroughTransformer(),
    AESTransformer('password', False),
    AESTransformer('password', True),
    AESTransformer('password', True, bytes_encoder=(lambda x: b64encode(x).decode('ascii')), bytes_decoder=(lambda x: b64decode(x.encode('ascii')))),
    HmacTransformer(),
    HmacTransformer('password'),
    GzipTransformer(),
    PipelineTransformer([HmacTransformer(), AESTransformer('password', False)]),
]


class Settings(NamedTuple):
    backend: DictatureBackendMock
    name_transformer: MockTransformer
    value_transformer: MockTransformer
    table_name_transformer: Optional[MockTransformer]


SETTINGS = [
    (Settings(backend, name_transformer, value_transformer, table_name_transformer),)
    for backend, name_transformer, value_transformer, table_name_transformer in product(BACKENDS, TRANSFORMERS, TRANSFORMERS, [*TRANSFORMERS, None])
]


class TestOperations(unittest.TestCase):
    def setUp(self):
        self.backend = None

    def tearDown(self):
        if self.backend:
            for table in self.backend.keys():
                del self.backend[table]

    @parameterized.expand(SETTINGS)
    def test_basic_set_and_get(self, settings: Settings):
        self.backend = Dictature(
            backend=settings.backend,
            name_transformer=settings.name_transformer,
            value_transformer=settings.value_transformer,
            table_name_transformer=settings.table_name_transformer
        )
        table = self.backend['table']
        table['key'] = 'value'
        table['key2'] = 'value2'
        table['key'] = 'value3'
        self.backend['table2']['key'] = 'value'
        self.assertEqual(table['key'], 'value3')
        self.assertEqual(table.keys(), {'key', 'key2'})
        self.assertEqual(self.backend.keys(), {'table', 'table2'})

    @parameterized.expand(SETTINGS)
    def test_saving_json_value(self, settings: Settings):
        self.backend = Dictature(
            backend=settings.backend,
            name_transformer=settings.name_transformer,
            value_transformer=settings.value_transformer,
            table_name_transformer=settings.table_name_transformer
        )
        value = {'key': 'value'}
        self.backend['table']['key'] = value
        self.assertDictEqual(self.backend['table']['key'], value)
        self.backend['table']['key'] = 2
        self.assertEqual(self.backend['table']['key'], 2)

    @parameterized.expand(SETTINGS)
    def test_saving_pickle_value(self, settings: Settings):
        self.backend = Dictature(
            backend=settings.backend,
            name_transformer=settings.name_transformer,
            value_transformer=settings.value_transformer,
            table_name_transformer=settings.table_name_transformer
        )
        self.backend['table']['key'] = NamedTuple
        self.assertEqual(self.backend['table']['key'], NamedTuple)

    @parameterized.expand(SETTINGS)
    def test_deletion_of_table_key(self, settings: Settings):
        self.backend = Dictature(
            backend=settings.backend,
            name_transformer=settings.name_transformer,
            value_transformer=settings.value_transformer,
            table_name_transformer=settings.table_name_transformer
        )
        table = self.backend['table']
        table['key'] = 'value'
        table['key2'] = 'value2'
        del table['key']
        self.assertEqual({'key2'}, table.keys())

    @parameterized.expand(SETTINGS)
    def test_deletion_of_whole_table(self, settings: Settings):
        self.backend = Dictature(
            backend=settings.backend,
            name_transformer=settings.name_transformer,
            value_transformer=settings.value_transformer,
            table_name_transformer=settings.table_name_transformer
        )
        self.backend['table2']['key'] = 'value'
        self.backend['table']['key'] = 'value'
        del self.backend['table']
        self.assertEqual(self.backend.keys(), {'table2'})


if __name__ == '__main__':
    unittest.main()
