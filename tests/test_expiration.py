"""Tests for ExpirationTransformer using time.time mocking."""
import unittest
from unittest.mock import patch

from src.dictature.transformer.expiration import ExpirationTransformer

_TIME_PATH = 'src.dictature.transformer.expiration.time'


class TestExpirationTransformerForward(unittest.TestCase):
    def test_forward_produces_string(self):
        with patch(_TIME_PATH, return_value=1_000_000.0):
            result = ExpirationTransformer(60).forward('hello')
        self.assertIsInstance(result, str)

    def test_forward_embeds_correct_expiry(self):
        with patch(_TIME_PATH, return_value=1_000_000.0):
            result = ExpirationTransformer(60).forward('hello')
        expiry_str, original = result.split('-', 1)
        self.assertAlmostEqual(float(expiry_str), 1_000_060.0, places=3)
        self.assertEqual(original, 'hello')

    def test_forward_different_times_produce_different_output(self):
        with patch(_TIME_PATH, return_value=1_000_000.0):
            r1 = ExpirationTransformer(60).forward('x')
        with patch(_TIME_PATH, return_value=1_000_010.0):
            r2 = ExpirationTransformer(60).forward('x')
        self.assertNotEqual(r1, r2)

    def test_forward_preserves_hyphens_in_value(self):
        with patch(_TIME_PATH, return_value=1_000_000.0):
            result = ExpirationTransformer(60).forward('foo-bar-baz')
        _, original = result.split('-', 1)
        self.assertEqual(original, 'foo-bar-baz')

    def test_is_not_static(self):
        self.assertFalse(ExpirationTransformer(60).static)


class TestExpirationTransformerBackward(unittest.TestCase):
    def _write_then_read(self, ttl, write_time, read_time, value='hello'):
        with patch(_TIME_PATH, return_value=write_time):
            stored = ExpirationTransformer(ttl).forward(value)
        with patch(_TIME_PATH, return_value=read_time):
            return ExpirationTransformer(ttl).backward(stored)

    def test_round_trip_immediately(self):
        result = self._write_then_read(ttl=60, write_time=1_000_000.0, read_time=1_000_000.0)
        self.assertEqual(result, 'hello')

    def test_round_trip_just_before_expiry(self):
        result = self._write_then_read(ttl=60, write_time=1_000_000.0, read_time=1_000_059.9)
        self.assertEqual(result, 'hello')

    def test_valid_exactly_at_expiry_boundary(self):
        # Condition is strict (>), so at t == expiry the value is still valid
        result = self._write_then_read(ttl=60, write_time=1_000_000.0, read_time=1_000_060.0)
        self.assertEqual(result, 'hello')

    def test_raises_just_after_expiry(self):
        with patch(_TIME_PATH, return_value=1_000_000.0):
            stored = ExpirationTransformer(60).forward('hello')
        with patch(_TIME_PATH, return_value=1_000_060.001):
            with self.assertRaises(KeyError):
                ExpirationTransformer(60).backward(stored)

    def test_raises_long_after_expiry(self):
        with patch(_TIME_PATH, return_value=1_000_000.0):
            stored = ExpirationTransformer(60).forward('hello')
        with patch(_TIME_PATH, return_value=2_000_000.0):
            with self.assertRaises(KeyError):
                ExpirationTransformer(60).backward(stored)

    def test_expired_raises_key_error_type(self):
        with patch(_TIME_PATH, return_value=1_000_000.0):
            stored = ExpirationTransformer(60).forward('hello')
        with patch(_TIME_PATH, return_value=1_000_999.0):
            with self.assertRaises(KeyError):
                ExpirationTransformer(60).backward(stored)

    def test_round_trip_preserves_hyphens(self):
        result = self._write_then_read(ttl=60, write_time=1_000_000.0, read_time=1_000_000.0,
                                       value='foo-bar-baz')
        self.assertEqual(result, 'foo-bar-baz')

    def test_short_ttl_expires_before_long_ttl(self):
        write_time = 1_000_000.0
        read_time = 1_000_050.0
        with patch(_TIME_PATH, return_value=write_time):
            stored_short = ExpirationTransformer(30).forward('x')
            stored_long = ExpirationTransformer(100).forward('x')
        with patch(_TIME_PATH, return_value=read_time):
            with self.assertRaises(KeyError):
                ExpirationTransformer(30).backward(stored_short)
            self.assertEqual(ExpirationTransformer(100).backward(stored_long), 'x')


if __name__ == '__main__':
    unittest.main()
