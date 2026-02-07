import os
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
from src.dictature.backend.single_table import DictatureSingleTableBackend
from src.dictature.transformer import PassthroughTransformer, PipelineTransformer
from src.dictature.transformer.mock import MockTransformer
from src.dictature.transformer.aes import AESTransformer
from src.dictature.transformer.hmac import HmacTransformer
from src.dictature.transformer.gzip import GzipTransformer


def initialize_extra_backends() -> list:
    """Add optional backends that depend on external services."""
    backends = []

    # Add Baserow backend if credentials are available
    baserow_token = os.getenv('BASEROW_TOKEN')
    baserow_table_id = os.getenv('BASEROW_TABLE_ID')
    baserow_url = os.getenv('BASEROW_URL', 'https://api.baserow.io')
    if baserow_token and baserow_table_id:
        try:
            from src.dictature.backend.baserow import DictatureBackendBaserowSingleTable
            backends.append(DictatureBackendBaserowSingleTable(
                token=baserow_token,
                table_id=int(baserow_table_id),
                base_url=baserow_url
            ))
        except (ImportError, ValueError) as e:
            print(f"Warning: Could not load Baserow backend: {e}")
    else:
        print("Warning: BASEROW_TOKEN and BASEROW_TABLE_ID not set. Baserow backend will be skipped.")

    # Add MISP backend if credentials are available
    misp_url = os.getenv('MISP_URL')
    misp_key = os.getenv('MISP_KEY')
    if misp_url and misp_key:
        try:
            from pymisp import PyMISP
            from src.dictature.backend.misp import DictatureBackendMISP
            misp_instance = PyMISP(misp_url, misp_key, ssl=os.getenv('MISP_SSL', 'true').lower() == 'true')
            backends.append(DictatureBackendMISP(misp_instance))
        except ImportError as e:
            print(f"Warning: Could not load MISP backend: {e}")
    else:
        print("Warning: MISP_URL and MISP_KEY not set. MISP backend will be skipped.")

    # Add MySQL backend if credentials are available
    mysql_host = os.getenv('MYSQL_HOST')
    mysql_user = os.getenv('MYSQL_USER')
    mysql_password = os.getenv('MYSQL_PASSWORD')
    mysql_database = os.getenv('MYSQL_DATABASE')
    if mysql_host and mysql_user and mysql_password and mysql_database:
        try:
            from src.dictature.backend.mysql import DictatureBackendMySQL
            mysql_port = int(os.getenv('MYSQL_PORT', '3306'))
            backends.append(DictatureBackendMySQL(
                host=mysql_host,
                port=mysql_port,
                user=mysql_user,
                password=mysql_password,
                database=mysql_database
            ))
        except (ImportError, ValueError) as e:
            print(f"Warning: Could not load MySQL backend: {e}")
    else:
        print("Warning: MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, and MYSQL_DATABASE not set. MySQL backend will be skipped.")

    # Add S3 backend if credentials are available
    s3_bucket = os.getenv('S3_BUCKET')
    if s3_bucket:
        try:
            from src.dictature.backend.s3 import DictatureBackendS3
            backends.append(DictatureBackendS3(
                bucket_name=s3_bucket,
                aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
                aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY'],
                region_name=os.getenv('AWS_REGION', 'us-east-1'),
                endpoint_url=os.environ['S3_ENDPOINT_URL']
            ))
        except ImportError as e:
            print(f"Warning: Could not load S3 backend: {e}")
    else:
        print("Warning: S3_BUCKET not set. S3 backend will be skipped.")

    # Add WebDAV backend if credentials are available
    webdav_url = os.getenv('WEBDAV_URL')
    webdav_login = os.getenv('WEBDAV_LOGIN')
    webdav_password = os.getenv('WEBDAV_PASSWORD')
    if webdav_url and webdav_login and webdav_password:
        try:
            from webdav3.client import Client as WebdavClient
            from src.dictature.backend.webdav import DictatureBackendWebdav
            webdav_client = WebdavClient({
                'webdav_hostname': webdav_url,
                'webdav_login': webdav_login,
                'webdav_password': webdav_password,
                'disable_check': True,
            })
            backends.append(DictatureBackendWebdav(client=webdav_client))
        except ImportError as e:
            print(f"Warning: Could not load WebDAV backend: {e}")
    else:
        print("Warning: WEBDAV_URL, WEBDAV_LOGIN, and WEBDAV_PASSWORD not set. WebDAV backend will be skipped.")

    confluence_url = os.getenv('CONFLUENCE_URL')
    confluence_user = os.getenv('CONFLUENCE_USER')
    confluence_token = os.getenv('CONFLUENCE_TOKEN')
    confluence_root_page = os.getenv('CONFLUENCE_ROOT_PAGE_ID')
    confluence_sync = os.getenv('CONFLUENCE_SYNC_PAGE_CONTENT', 'false').lower() == 'true'
    if confluence_url and confluence_user and confluence_token and confluence_root_page:
        try:
            from src.dictature.backend.confluence import DictatureBackendConfluence
            backends.append(DictatureBackendConfluence(
                base_url=confluence_url,
                username=confluence_user,
                api_token=confluence_token,
                root_page_id=confluence_root_page,
                sync_page_content=confluence_sync
            ))
        except ImportError as e:
            print(f"Warning: Could not load Confluence backend: {e}")
    else:
        print("Warning: CONFLUENCE_URL, CONFLUENCE_USER, CONFLUENCE_TOKEN, and CONFLUENCE_ROOT_PAGE_ID not set. Confluence backend will be skipped.")

    return backends


DEFAULT_BACKENDS = [  # Default backends are tested with all transformer combinations
    DictatureBackendDirectory(mkdtemp(prefix='dictature')),
    DictatureBackendSQLite(mktemp(prefix='dictature', suffix='.sqlite3')),
    DictatureSingleTableBackend(Dictature(DictatureBackendSQLite(mktemp(prefix='dictature_single_table', suffix='.sqlite3')), allow_pickle=True)['table']),
]
EXTRA_BACKENDS = initialize_extra_backends()  # Extra backends tested only with passthrough transformers


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


def get_transformer_name(transformer) -> str:
    """Get a readable name for a transformer."""
    if transformer is None:
        return "None"
    
    class_name = type(transformer).__name__
    
    # Handle specific transformer types with more details
    if class_name == "AESTransformer":
        # Check for base64 encoding by looking at attributes
        has_encoder = hasattr(transformer, 'bytes_encoder') and transformer.bytes_encoder is not None
        encoded = "_b64" if has_encoder else ""
        deterministic = "_det" if getattr(transformer, 'deterministic', False) else ""
        return f"AES{deterministic}{encoded}"
    elif class_name == "HmacTransformer":
        # Check if it has a password
        has_password = hasattr(transformer, '_key') and transformer._key != b''
        return "HMAC_pwd" if has_password else "HMAC"
    elif class_name == "PipelineTransformer":
        # Get names of transformers in the pipeline
        if hasattr(transformer, 'transformers'):
            pipeline_names = [get_transformer_name(t) for t in transformer.transformers]
            return f"Pipeline({'+'.join(pipeline_names)})"
        return "Pipeline"
    elif class_name == "PassthroughTransformer":
        return "Passthrough"
    elif class_name == "GzipTransformer":
        return "Gzip"
    
    return class_name


def get_backend_name(backend) -> str:
    """Get a readable name for a backend."""
    class_name = type(backend).__name__
    
    # Simplify common backend names
    if class_name.startswith("DictatureBackend"):
        return class_name.replace("DictatureBackend", "")
    
    return class_name


def get_name_func(testcase_func, param_num, param):
    """Generate readable test names from Settings."""
    settings = param.args[0]
    
    backend_name = get_backend_name(settings.backend)
    name_trans = get_transformer_name(settings.name_transformer)
    value_trans = get_transformer_name(settings.value_transformer)
    table_trans = get_transformer_name(settings.table_name_transformer)
    
    return f"{testcase_func.__name__}_{backend_name}__name_{name_trans}__value_{value_trans}__table_{table_trans}"


SETTINGS = [
    (Settings(backend, name_transformer, value_transformer, table_name_transformer),)
    for backend, name_transformer, value_transformer, table_name_transformer in product(DEFAULT_BACKENDS, TRANSFORMERS, TRANSFORMERS, [*TRANSFORMERS, None])
] + [
    (Settings(backend, PassthroughTransformer(), PassthroughTransformer(), PassthroughTransformer()),)
    for backend in EXTRA_BACKENDS
]


class TestOperations(unittest.TestCase):
    def setUp(self):
        self.backend = None

    def tearDown(self):
        if self.backend:
            for table in self.backend.keys():
                del self.backend[table]

    @parameterized.expand(SETTINGS, name_func=get_name_func)
    def test_simle_set_and_get(self, settings: Settings):
        self.backend = Dictature(
            backend=settings.backend,
            name_transformer=settings.name_transformer,
            value_transformer=settings.value_transformer,
            table_name_transformer=settings.table_name_transformer,
        )
        table = self.backend['table']
        table['key'] = 'value'
        table['key2'] = 'value2'
        table['key'] = 'value3'
        self.backend['table2']['key'] = 'value'
        self.assertEqual(table['key'], 'value3')
        self.assertEqual(table.keys(), {'key', 'key2'})
        self.assertEqual(self.backend.keys(), {'table', 'table2'})

    @parameterized.expand(SETTINGS, name_func=get_name_func)
    def test_traversal_set_and_get(self, settings: Settings):
        self.backend = Dictature(
            backend=settings.backend,
            name_transformer=settings.name_transformer,
            value_transformer=settings.value_transformer,
            table_name_transformer=settings.table_name_transformer
        )
        table = self.backend[r'..\..\..']
        table[r'..\..\..'] = r'../..\../'
        table[r'../../../'] = r'../..\..\.'
        self.backend[r'../../../'][r'..\..\..'] = r'../../../'
        self.assertEqual(table[r'..\..\..'], r'../..\../')
        self.assertEqual(table.keys(), {r'..\..\..', r'../../../'})
        self.assertEqual(self.backend.keys(), {r'..\..\..', r'../../../'})

    @parameterized.expand(SETTINGS, name_func=get_name_func)
    def test_special_set_and_get(self, settings: Settings):
        self.backend = Dictature(
            backend=settings.backend,
            name_transformer=settings.name_transformer,
            value_transformer=settings.value_transformer,
            table_name_transformer=settings.table_name_transformer
        )
        table = self.backend['✅']
        table['🔑'] = '⭐'
        table['🗝️'] = '✨'
        table['🔑'] = '🌟'
        self.backend['❌']['🔑'] = '🏚️'
        self.assertEqual(table['🔑'], '🌟')
        self.assertEqual(table.keys(), {'🔑', '🗝️'})
        self.assertEqual(self.backend.keys(), {'✅', '❌'})

    @parameterized.expand(SETTINGS, name_func=get_name_func)
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

    @parameterized.expand(SETTINGS, name_func=get_name_func)
    def test_saving_pickle_value(self, settings: Settings):
        self.backend = Dictature(
            backend=settings.backend,
            name_transformer=settings.name_transformer,
            value_transformer=settings.value_transformer,
            table_name_transformer=settings.table_name_transformer,
            allow_pickle=True,
        )
        self.backend['table']['key'] = NamedTuple
        self.assertEqual(self.backend['table']['key'], NamedTuple)

    @parameterized.expand(SETTINGS, name_func=get_name_func)
    def test_pickle_disabled_by_default(self, settings: Settings):
        self.backend = Dictature(
            backend=settings.backend,
            name_transformer=settings.name_transformer,
            value_transformer=settings.value_transformer,
            table_name_transformer=settings.table_name_transformer,
        )
        with self.assertRaises(ValueError):
            self.backend['table']['key'] = NamedTuple

    @parameterized.expand(SETTINGS, name_func=get_name_func)
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

    @parameterized.expand(SETTINGS, name_func=get_name_func)
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

    @parameterized.expand(SETTINGS, name_func=get_name_func)
    def test_bulk_storage_and_retrieval(self, settings: Settings):
        """Test storing and retrieving 110 key-value pairs to verify pagination works correctly."""
        self.backend = Dictature(
            backend=settings.backend,
            name_transformer=settings.name_transformer,
            value_transformer=settings.value_transformer,
            table_name_transformer=settings.table_name_transformer
        )
        table = self.backend['bulk_test']
        
        # Store 110 key-value pairs
        num_items = 110
        expected_data = {f'key_{i}': f'value_{i}' for i in range(1, num_items + 1)}
        
        for key, value in expected_data.items():
            table[key] = value
        
        # Verify all keys are present
        stored_keys = table.keys()
        self.assertEqual(stored_keys, set(expected_data.keys()))
        
        # Verify all values are correct
        for key, expected_value in expected_data.items():
            self.assertEqual(table[key], expected_value)


if __name__ == '__main__':
    unittest.main()
