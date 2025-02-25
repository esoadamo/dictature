# SQLiDictature

A wrapper for Python's dictionary with multiple backends.

## Installation

```shell
pip install dictature
```

## Dictature usage
This package also includes a class that allows you to use your SQLite db as a Python dictionary:

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
