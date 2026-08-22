# Dictature

Make a Python dictionary out of anything.  A wrapper for Python's dictionary with multiple backends.
Thread-safe, supports multiple backends, and allows for transformers to change how the data is stored.

SQLite, directory, webdav, and more backends are supported, and you can easily create your own backend.

[![PyPI version](https://badge.fury.io/py/dictature.svg)](https://badge.fury.io/py/dictature)

## Installation

```shell
# Base installation (SQLite, Directory, SingleTable, Gzip, HMAC, Expiration)
pip install dictature
# or with uv
uv add dictature

# With specific backend/feature dependencies
pip install dictature[mysql]         # MySQL backend
pip install dictature[s3]            # S3 / S3-compatible backend
pip install dictature[webdav]        # WebDAV backend
pip install dictature[confluence]    # Confluence backend
pip install dictature[baserow]       # Baserow backend
pip install dictature[misp]          # MISP backend
pip install dictature[encryption]    # AES encryption transformer

# Install all backend and transformer dependencies
pip install dictature[full]
# or with uv
uv add "dictature[full]"
```

## Dictature usage
This package also includes a class that allows you to use your SQLite db or any backend as a Python dictionary.

### Quickstart

First step is to create a backend, then first level is table name and second level are actual keys:
```python
from dictature import Dictature
dictionary = Dictature.sqlite('test_data.sqlite3')

# will create a table db_test and there a row called foo with value bar
dictionary['test']['foo'] = 'bar'

# also support anything that can be jsonized
dictionary['test']['list'] = ['1', 2, True]
print(dictionary['test']['list'])  # prints ['1', 2, True]

# or anything, really (that can be serialized with pickle)
from threading import Thread
dictionary = dictionary.with_pickle(allow_pickle=True)
dictionary['test']['thread'] = Thread
print(dictionary['test']['thread'])  # prints <class 'threading.Thread'>

# and deleting
del dictionary['test']['list']  # deletes the record
del dictionary['test']  # drops whole table
```

Each built-in backend has a convenient classmethod constructor on `Dictature`:

```python
from dictature import Dictature

# SQLite (built-in, no extra deps)
dictionary = Dictature.sqlite('test_data.sqlite3')
dictionary = Dictature.sqlite(':memory:')          # in-memory

# Directory — stores each value as a file
dictionary = Dictature.directory('test_data/')

# Single-table — virtualises multiple tables inside one existing DictatureTable
base = Dictature.sqlite('test_data.sqlite3')
dictionary = Dictature.single_table(base['storage'])

# MySQL (pip install mysql-connector-python)
dictionary = Dictature.mysql(host='localhost', user='root', password='secret', database='mydb')

# S3 / S3-compatible (pip install boto3)
dictionary = Dictature.s3('my-bucket', aws_access_key_id='...', aws_secret_access_key='...')
dictionary = Dictature.s3('my-bucket', endpoint_url='http://localhost:9000')  # MinIO etc.

# WebDAV (pip install webdavclient3)
dictionary = Dictature.webdav('https://dav.example.com/', login='user', password='secret')

# Confluence (pip install requests)
dictionary = Dictature.confluence('https://yoursite.atlassian.net/wiki', 'user@example.com', 'api-token', 'PAGE_ID')

# Baserow (pip install requests)
dictionary = Dictature.baserow(token='my-token', table_id=42)

# MISP (pip install pymisp)
dictionary = Dictature.misp('https://misp.example.com', 'api-key')
```

Alternatively, construct backends directly:

```python
from dictature import Dictature
from dictature.backend import DictatureBackendDirectory, DictatureBackendSQLite

# will use/create the db directory
# dictionary = Dictature(DictatureBackendDirectory('test_data'))
# will use/create the db file
dictionary = Dictature(DictatureBackendSQLite('test_data.sqlite3'))

# will create a table db_test and there a row called foo with value bar
dictionary['test']['foo'] = 'bar'

# also support anything that can be jsonized
dictionary['test']['list'] = ['1', 2, True]
print(dictionary['test']['list'])  # prints ['1', 2, True]

# or anything, really (that can be serialized with pickle)
from threading import Thread
dictionary['test']['thread'] = Thread
print(dictionary['test']['thread'])  # prints <class 'threading.Thread'>

# and deleting
del dictionary['test']['list']  # deletes the record
del dictionary['test']  # drops whole table
```

Currently, the following backends are supported:
- `DictatureBackendDirectory`: stores the data in a directory as json files
- `DictatureBackendSQLite`: stores the data in a SQLite database
- `DictatureBackendMISP`: stores the data in a MISP instance
- `DictatureBackendWebdav`: stores data in a WebDav share as files
- `DictatureBackendS3`: stores data in an S3 bucket
- `DictatureBackendMySQL`: stores data in a MySQL database
- `DictatureBackendBaserow`: stores data in a Baserow database
- `DictatureSingleTableBackend`: virtual backend that stores all data in a single Dictature table
- `DictatureBackendConfluence`: stores the data in a Confluence instance

### Transformers via `with_*` chaining

After creating an instance with any backend method, you can chain `with_*` calls to layer
transformers without touching the underlying backend:

```python
from dictature import Dictature

# Compress all stored values (gzip + base64 — no extra deps)
dictionary = Dictature.sqlite('data.sqlite3').with_compression()

# Encrypt values with AES-GCM; also encrypt key names with AES-ECB
dictionary = Dictature.sqlite('data.sqlite3').with_encryption('my-passphrase', names=True)

# Add HMAC integrity checking to key names (raises ValueError on tampered keys)
dictionary = Dictature.sqlite('data.sqlite3').with_hmac('my-secret')

# Chain multiple transformers: encrypt then compress
dictionary = (
    Dictature.sqlite('data.sqlite3')
    .with_encryption('my-passphrase')
    .with_compression()
)
```

All three methods accept the same `values`, `names`, and `table_names` boolean flags so you can
decide exactly what gets transformed.

### Transformers

You can also use transformers to change how the values are stored. E.g. to encrypt data, you can use the
`AESTransformer` (which requires the `pycryptodome` package):

```python
from dictature import Dictature
from dictature.backend import DictatureBackendDirectory
from dictature.transformer.aes import AESTransformer

name_transformer = AESTransformer('password1', True)
value_transformer = AESTransformer('password2', False)

dictionary = Dictature(
    DictatureBackendSQLite('test_data.sqlite3'),
    name_transformer=name_transformer,
    value_transformer=value_transformer
)
```

Currently, the following transformers are supported:
- `AESTransformer`: encrypts/decrypts the data using AES
- `HmacTransformer`: signs the data using HMAC or performs hash integrity checks
- `GzipTransformer`: compresses given data
- `ExpirationTransformer`: expires data after a given time
- `PassthroughTransformer`: does nothing
- `PipelineTransformer`: chains multiple transformers

## Testing

All tests are located inside `tests` folder. However, by default only backends that do not require any additonal
service running are tested. If you want to test all the self-hostable backends, either setup environment variables
for access or run `run_tests_with_backends.py` script that will create temporary backends for you via `podman-compose`.