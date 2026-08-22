"""Tests for Dictature classmethod constructors and with_* transformer helpers."""
import importlib.util
import unittest
from tempfile import mkdtemp, mktemp
from unittest.mock import patch

from src.dictature import Dictature
from src.dictature.backend.sqlite import DictatureBackendSQLite
from src.dictature.backend.directory import DictatureBackendDirectory
from src.dictature.backend.single_table import DictatureSingleTableBackend
from src.dictature.transformer.pipeline import PipelineTransformer


def _backend(d: Dictature):
    return d._Dictature__backend


def _value_transformer(d: Dictature):
    return d._Dictature__value_transformer


def _name_transformer(d: Dictature):
    return d._Dictature__name_transformer


def _has_package(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


# ---------------------------------------------------------------------------
# Backend classmethods — creation tests
# ---------------------------------------------------------------------------

class TestSqliteClassmethod(unittest.TestCase):
    def test_returns_dictature(self):
        self.assertIsInstance(Dictature.sqlite(':memory:'), Dictature)

    def test_correct_backend(self):
        self.assertIsInstance(_backend(Dictature.sqlite(':memory:')), DictatureBackendSQLite)

    def test_file_path(self):
        self.assertIsInstance(_backend(Dictature.sqlite(mktemp(suffix='.sqlite3'))), DictatureBackendSQLite)


class TestDirectoryClassmethod(unittest.TestCase):
    def test_returns_dictature(self):
        self.assertIsInstance(Dictature.directory(mkdtemp()), Dictature)

    def test_correct_backend(self):
        self.assertIsInstance(_backend(Dictature.directory(mkdtemp())), DictatureBackendDirectory)


class TestSingleTableClassmethod(unittest.TestCase):
    def setUp(self):
        self.base = Dictature.sqlite(':memory:')

    def test_returns_dictature(self):
        self.assertIsInstance(Dictature.single_table(self.base['storage']), Dictature)

    def test_correct_backend(self):
        self.assertIsInstance(_backend(Dictature.single_table(self.base['storage'])), DictatureSingleTableBackend)


@unittest.skipUnless(_has_package('mysql'), 'mysql-connector-python not installed')
class TestMysqlClassmethod(unittest.TestCase):
    def test_returns_dictature(self):
        from unittest.mock import MagicMock, patch
        with patch('src.dictature.backend.mysql.mysql.connector.connect', return_value=MagicMock(cursor=MagicMock())):
            self.assertIsInstance(Dictature.mysql('localhost', user='u', password='p', database='db'), Dictature)

    def test_correct_backend(self):
        from unittest.mock import MagicMock, patch
        from src.dictature.backend.mysql import DictatureBackendMySQL
        with patch('src.dictature.backend.mysql.mysql.connector.connect', return_value=MagicMock(cursor=MagicMock())):
            self.assertIsInstance(_backend(Dictature.mysql('localhost', user='u', password='p', database='db')), DictatureBackendMySQL)


@unittest.skipUnless(_has_package('boto3'), 'boto3 not installed')
class TestS3Classmethod(unittest.TestCase):
    def test_returns_dictature(self):
        from unittest.mock import MagicMock, patch
        with patch('src.dictature.backend.s3.boto3.resource', return_value=MagicMock()):
            self.assertIsInstance(Dictature.s3('my-bucket'), Dictature)

    def test_correct_backend(self):
        from unittest.mock import MagicMock, patch
        from src.dictature.backend.s3 import DictatureBackendS3
        with patch('src.dictature.backend.s3.boto3.resource', return_value=MagicMock()):
            self.assertIsInstance(_backend(Dictature.s3('my-bucket')), DictatureBackendS3)


@unittest.skipUnless(_has_package('webdav3'), 'webdavclient3 not installed')
class TestWebdavClassmethod(unittest.TestCase):
    def test_returns_dictature(self):
        from unittest.mock import patch
        with patch('webdav3.client.Client.__init__', return_value=None):
            self.assertIsInstance(Dictature.webdav('https://dav.example.com/'), Dictature)

    def test_correct_backend(self):
        from unittest.mock import patch
        from src.dictature.backend.webdav import DictatureBackendWebdav
        with patch('webdav3.client.Client.__init__', return_value=None):
            self.assertIsInstance(_backend(Dictature.webdav('https://dav.example.com/')), DictatureBackendWebdav)


@unittest.skipUnless(_has_package('requests'), 'requests not installed')
class TestConfluenceClassmethod(unittest.TestCase):
    def test_returns_dictature(self):
        self.assertIsInstance(
            Dictature.confluence('https://example.atlassian.net/wiki', 'user', 'token', 'PAGE_ID'), Dictature
        )

    def test_correct_backend(self):
        from src.dictature.backend.confluence import DictatureBackendConfluence
        self.assertIsInstance(
            _backend(Dictature.confluence('https://example.atlassian.net/wiki', 'user', 'token', 'PAGE_ID')),
            DictatureBackendConfluence,
        )


@unittest.skipUnless(_has_package('requests'), 'requests not installed')
class TestBaserowClassmethod(unittest.TestCase):
    def test_returns_dictature(self):
        self.assertIsInstance(Dictature.baserow(token='my-token', table_id=42), Dictature)

    def test_correct_backend(self):
        from src.dictature.backend.baserow import DictatureBackendBaserowSingleTable
        self.assertIsInstance(_backend(Dictature.baserow(token='my-token', table_id=42)), DictatureBackendBaserowSingleTable)


@unittest.skipUnless(_has_package('pymisp'), 'pymisp not installed')
class TestMispClassmethod(unittest.TestCase):
    def test_returns_dictature(self):
        from unittest.mock import patch
        with patch('pymisp.PyMISP.__init__', return_value=None):
            self.assertIsInstance(Dictature.misp('https://misp.example.com', 'api-key'), Dictature)

    def test_correct_backend(self):
        from unittest.mock import patch
        from src.dictature.backend.misp import DictatureBackendMISP
        with patch('pymisp.PyMISP.__init__', return_value=None):
            self.assertIsInstance(_backend(Dictature.misp('https://misp.example.com', 'api-key')), DictatureBackendMISP)


# ---------------------------------------------------------------------------
# with_compression
# ---------------------------------------------------------------------------

class TestWithCompression(unittest.TestCase):
    def _make(self, **kwargs) -> Dictature:
        return Dictature.sqlite(':memory:').with_compression(**kwargs)

    def test_returns_self(self):
        d = Dictature.sqlite(':memory:')
        self.assertIs(d.with_compression(), d)

    def test_value_transformer_is_pipeline(self):
        self.assertIsInstance(_value_transformer(self._make()), PipelineTransformer)

    def test_round_trip_string(self):
        d = self._make()
        d['t']['k'] = 'hello world'
        self.assertEqual(d['t']['k'], 'hello world')

    def test_round_trip_complex(self):
        d = self._make()
        d['t']['k'] = {'list': [1, 2, 3], 'nested': {'a': True}}
        self.assertEqual(d['t']['k'], {'list': [1, 2, 3], 'nested': {'a': True}})

    def test_stored_value_is_not_plaintext(self):
        d = self._make()
        d['t']['k'] = 'hello world'
        raw = _backend(d)._execute("SELECT value FROM `tb_t` WHERE key='k'")[0][0]
        self.assertNotEqual(raw, 'hello world')

    def test_names_compression(self):
        d = self._make(values=False, names=True, table_names=False)
        d['t']['my_key'] = 'value'
        self.assertEqual(d['t']['my_key'], 'value')
        # Raw stored key should not be 'my_key'
        raw_keys = [r[0] for r in _backend(d)._execute("SELECT key FROM `tb_t`")]
        self.assertNotIn('my_key', raw_keys)


# ---------------------------------------------------------------------------
# with_encryption
# ---------------------------------------------------------------------------

class TestWithEncryption(unittest.TestCase):
    def _make(self, **kwargs) -> Dictature:
        return Dictature.sqlite(':memory:').with_encryption('secret-pass', **kwargs)

    def test_returns_self(self):
        d = Dictature.sqlite(':memory:')
        self.assertIs(d.with_encryption('secret'), d)

    def test_value_transformer_is_pipeline(self):
        self.assertIsInstance(_value_transformer(self._make()), PipelineTransformer)

    def test_round_trip_string(self):
        d = self._make()
        d['t']['k'] = 'hello world'
        self.assertEqual(d['t']['k'], 'hello world')

    def test_round_trip_complex(self):
        d = self._make()
        d['t']['k'] = [1, 'two', None]
        self.assertEqual(d['t']['k'], [1, 'two', None])

    def test_stored_value_is_not_plaintext(self):
        d = self._make()
        d['t']['k'] = 'hello world'
        raw = _backend(d)._execute("SELECT value FROM `tb_t` WHERE key='k'")[0][0]
        self.assertNotEqual(raw, 'hello world')

    def test_name_encryption(self):
        d = self._make(names=True, table_names=False)
        d['t']['my_key'] = 'value'
        self.assertEqual(d['t']['my_key'], 'value')
        raw_keys = [r[0] for r in _backend(d)._execute("SELECT key FROM `tb_t`")]
        self.assertNotIn('my_key', raw_keys)

    def test_wrong_passphrase_raises(self):
        d1 = Dictature.sqlite(':memory:').with_encryption('correct')
        d1['t']['k'] = 'secret'

        # Re-open with wrong passphrase — the raw ciphertext is in d1's backend
        backend = _backend(d1)
        from src.dictature import Dictature as D
        from src.dictature.backend.mock import DictatureBackendMock
        d2 = D(backend)
        d2.with_encryption('wrong')
        with self.assertRaises(Exception):
            _ = d2['t']['k']


# ---------------------------------------------------------------------------
# with_hmac
# ---------------------------------------------------------------------------

class TestWithHmac(unittest.TestCase):
    def _make(self, **kwargs) -> Dictature:
        return Dictature.sqlite(':memory:').with_hmac('my-secret', **kwargs)

    def test_returns_self(self):
        d = Dictature.sqlite(':memory:')
        self.assertIs(d.with_hmac(), d)

    def test_name_transformer_is_pipeline_by_default(self):
        # Default: names=True
        self.assertIsInstance(_name_transformer(self._make()), PipelineTransformer)

    def test_round_trip_with_name_hmac(self):
        d = self._make(names=True, values=False)
        d['t']['my_key'] = 'hello'
        self.assertEqual(d['t']['my_key'], 'hello')

    def test_round_trip_with_value_hmac(self):
        d = self._make(values=True, names=False)
        d['t']['k'] = 'hello world'
        self.assertEqual(d['t']['k'], 'hello world')

    def test_stored_key_has_hmac_prefix(self):
        d = self._make(names=True, values=False, table_names=False)
        d['t']['k'] = 'val'
        raw_keys = [r[0] for r in _backend(d)._execute("SELECT key FROM `tb_t`")]
        # HMAC forward wraps as "<hmac_hex>-k", so raw key != 'k'
        self.assertNotIn('k', raw_keys)
        # And the raw key contains a '-' separator
        self.assertTrue(any('-' in rk for rk in raw_keys))

    def test_stored_value_has_hmac_prefix(self):
        d = self._make(values=True, names=False)
        d['t']['k'] = 'hello'
        raw = _backend(d)._execute("SELECT value FROM `tb_t` WHERE key='k'")[0][0]
        self.assertNotEqual(raw, 'hello')
        self.assertIn('-', raw)

    def test_tampered_value_raises(self):
        d = self._make(values=True, names=False)
        d['t']['k'] = 'original'
        # Tamper with the raw stored value
        _backend(d)._execute("UPDATE `tb_t` SET value='tampered-value' WHERE key='k'")
        _backend(d)._commit()
        with self.assertRaises(ValueError):
            _ = d['t']['k']


# ---------------------------------------------------------------------------
# with_expiration
# ---------------------------------------------------------------------------

_EXPIRATION_TIME_PATH = 'src.dictature.transformer.expiration.time'


class TestWithExpiration(unittest.TestCase):
    def test_returns_self(self):
        with patch(_EXPIRATION_TIME_PATH, return_value=1_000_000.0):
            d = Dictature.sqlite(':memory:')
            self.assertIs(d.with_expiration(60), d)

    def test_value_transformer_is_pipeline(self):
        with patch(_EXPIRATION_TIME_PATH, return_value=1_000_000.0):
            d = Dictature.sqlite(':memory:').with_expiration(60)
        self.assertIsInstance(_value_transformer(d), PipelineTransformer)

    def test_round_trip_before_expiry(self):
        with patch(_EXPIRATION_TIME_PATH, return_value=1_000_000.0):
            d = Dictature.sqlite(':memory:').with_expiration(60)
            d['t']['k'] = 'hello'
        with patch(_EXPIRATION_TIME_PATH, return_value=1_000_001.0):
            self.assertEqual(d['t']['k'], 'hello')

    def test_round_trip_complex_value(self):
        with patch(_EXPIRATION_TIME_PATH, return_value=1_000_000.0):
            d = Dictature.sqlite(':memory:').with_expiration(60)
            d['t']['k'] = {'list': [1, 2], 'flag': True}
        with patch(_EXPIRATION_TIME_PATH, return_value=1_000_001.0):
            self.assertEqual(d['t']['k'], {'list': [1, 2], 'flag': True})

    def test_value_still_readable_just_before_expiry(self):
        with patch(_EXPIRATION_TIME_PATH, return_value=1_000_000.0):
            d = Dictature.sqlite(':memory:').with_expiration(60)
            d['t']['k'] = 'hello'
        with patch(_EXPIRATION_TIME_PATH, return_value=1_000_059.9):
            self.assertEqual(d['t']['k'], 'hello')

    def test_expired_value_raises_key_error(self):
        with patch(_EXPIRATION_TIME_PATH, return_value=1_000_000.0):
            d = Dictature.sqlite(':memory:').with_expiration(60)
            d['t']['k'] = 'hello'
        with patch(_EXPIRATION_TIME_PATH, return_value=1_000_061.0):
            with self.assertRaises(KeyError):
                _ = d['t']['k']

    def test_different_keys_can_have_different_write_times(self):
        d = Dictature.sqlite(':memory:').with_expiration(60)
        with patch(_EXPIRATION_TIME_PATH, return_value=1_000_000.0):
            d['t']['early'] = 'first'
        with patch(_EXPIRATION_TIME_PATH, return_value=1_000_050.0):
            d['t']['late'] = 'second'
        with patch(_EXPIRATION_TIME_PATH, return_value=1_000_065.0):
            # early: written at t=0, expires at t=60 → expired at t=65
            with self.assertRaises(KeyError):
                _ = d['t']['early']
            # late: written at t=50, expires at t=110 → still valid at t=65
            self.assertEqual(d['t']['late'], 'second')

    def test_rewriting_resets_expiry(self):
        d = Dictature.sqlite(':memory:').with_expiration(60)
        with patch(_EXPIRATION_TIME_PATH, return_value=1_000_000.0):
            d['t']['k'] = 'first'
        with patch(_EXPIRATION_TIME_PATH, return_value=1_000_050.0):
            d['t']['k'] = 'renewed'
        with patch(_EXPIRATION_TIME_PATH, return_value=1_000_100.0):
            # 100s since first write, but only 50s since rewrite → still valid
            self.assertEqual(d['t']['k'], 'renewed')

    def test_stored_value_contains_timestamp(self):
        with patch(_EXPIRATION_TIME_PATH, return_value=1_000_000.0):
            d = Dictature.sqlite(':memory:').with_expiration(60)
            d['t']['k'] = 'hello'
        raw = _backend(d)._execute("SELECT value FROM `tb_t` WHERE key='k'")[0][0]
        self.assertNotEqual(raw, 'hello')
        self.assertIn('-', raw)


if __name__ == '__main__':
    unittest.main()
