from json import dumps, loads
from string import hexdigits, ascii_letters, digits, printable
from typing import Iterable, NamedTuple
from enum import Enum


class ValueMode(Enum):
    string = 0
    json = 1
    pickle = 2


class Value(NamedTuple):
    value: str
    mode: int


class ValueSerializerMode(Enum):
    any_string = 0
    ascii_only = 1
    filename_only = 2
    hex_only = 3


class ValueSerializer:
    prefix = 'a09e'

    def __init__(self, mode: ValueSerializerMode = ValueSerializerMode.any_string):
        self.__mode = mode

    def deserialize(self, serialized: str) -> Value:
        """
        Deserialize a string into a Value object
        :param serialized: serialized string
        :return: Value object
        """
        # Check if the string starts with the prefix (hex-encoded)
        if serialized.startswith(self.prefix):
            # Decode the hex part
            hex_data = serialized[len(self.prefix):]
            decoded = bytes.fromhex(hex_data).decode('ascii')
            # Recursively deserialize the decoded string
            return ValueSerializer(mode=ValueSerializerMode.ascii_only).deserialize(decoded)

        # Check if the string looks like JSON
        if serialized.startswith('{'):
            try:
                data = loads(serialized)
                return Value(value=data['value'], mode=data['mode'])
            except (ValueError, KeyError):
                pass  # Not valid JSON or missing required keys

        # Direct value (string mode)
        return Value(value=serialized, mode=ValueMode.string.value)

    def serialize(self, value: Value) -> str:
        """
        Serializes a `Value` object into a `str`, converting its data representation
        based on the serialization mode set in `ValueSerializerMode`. Depending on
        the mode provided, the object can be serialized directly if its string
        representation conforms to certain criteria, or it may be converted into
        a JSON format. Handles customization of allowed characters and uses prefix
        to encode conditions if the direct representation is not permitted.

        If the mode is incompatible or unsupported, raises a `NotImplementedError`.

        :param value: Instance of `Value` to be serialized.

        :return: Serialized representation of the `Value` object as a string.

        :raises NotImplementedError: If the mode provided in `ValueSerializerMode`
            is unsupported.
        """
        if self.__mode == ValueSerializerMode.hex_only:
            allowed_chars = hexdigits
        elif self.__mode == ValueSerializerMode.filename_only:
            allowed_chars = ascii_letters + digits + ' -_.'
        elif self.__mode in (ValueSerializerMode.any_string, ValueSerializerMode.ascii_only):
            allowed_chars = None
        else:
            raise NotImplementedError(self.__mode)

        if allowed_chars is not None:
            # Only a subset of characters is allowed if all match and do not start with the reserved prefix, encode directly
            if value.mode == ValueMode.string.value and all(map(lambda x: x in allowed_chars, value.value)) and not value.value.startswith(self.prefix):
                return value.value
            return self.prefix + ValueSerializer(mode=ValueSerializerMode.ascii_only).serialize(value).encode('ascii').hex()

        # Save as JSON if not string or value is starting with { (indicating JSON)
        save_as_json = value.mode != ValueMode.string.value or value.value.startswith('{') or value.value.startswith(self.prefix)
        # Save as JSON if only ASCII strings are allowed
        save_as_json = save_as_json or (self.__mode == ValueSerializerMode.ascii_only and any(filter(lambda x: x not in printable, value.value)))
        return dumps({'value': value.value, 'mode': value.mode}, indent=1) if save_as_json else value.value


class DictatureBackendMock:
    def keys(self) -> Iterable[str]:
        """
        Return all table names
        :return: all table names
        """
        raise NotImplementedError("This method should be implemented by the subclass")

    def table(self, name: str) -> 'DictatureTableMock':
        """
        Create a table object based on the name
        :param name: name of the table
        :return: table object
        """
        raise NotImplementedError("This method should be implemented by the subclass")


class DictatureTableMock:
    def keys(self) -> Iterable[str]:
        """
        Return all keys in the table
        :return: all keys in the table
        """
        raise NotImplementedError("This method should be implemented by the subclass")

    def drop(self) -> None:
        """
        Delete the table
        :return: None
        """
        raise NotImplementedError("This method should be implemented by the subclass")

    def create(self) -> None:
        """
        Create the table in the backend
        :return: None
        """
        raise NotImplementedError("This method should be implemented by the subclass")

    def set(self, item: str, value: Value) -> None:
        """
        Set a value in the table
        :param item: key to set
        :param value: value to set
        :return: None
        """
        raise NotImplementedError("This method should be implemented by the subclass")

    def get(self, item: str) -> Value:
        """
        Get a value from the table
        :param item: key to get
        :return: value
        :raises KeyError: if the key does not exist
        """
        raise NotImplementedError("This method should be implemented by the subclass")

    def delete(self, item: str) -> None:
        """
        Delete a value from the table
        :param item: key to delete
        :return: None
        """
        raise NotImplementedError("This method should be implemented by the subclass")