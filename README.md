# Dictature

Make a Python dictionary out of anything.  A wrapper for Python's dictionary with multiple backends.
Thread-safe, supports multiple backends, and allows for transformers to change how the data is stored.

SQLite, directory, webdav, and more backends are supported, and you can easily create your own backend.

[![PyPI version](https://badge.fury.io/py/dictature.svg)](https://badge.fury.io/py/dictature)

## Installation

```shell
pip install dictature
```

## Dictature usage
This package also includes a class that allows you to use your SQLite db or any backend as a Python dictionary:

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
- `PassthroughTransformer`: does nothing
- `PipelineTransformer`: chains multiple transformers
