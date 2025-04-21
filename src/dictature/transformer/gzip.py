import gzip
import base64

from .mock import MockTransformer


class GzipTransformer(MockTransformer):
    """
    Compresses and decompresses text using Gzip.

    The compressed data is Base64 encoded to ensure it can be represented as a string.
    """
    def __init__(self) -> None:
        """
        Initializes the GzipTransformer. No parameters needed for basic Gzip.
        """
        # No specific state needed for standard gzip compression/decompression
        pass

    def forward(self, text: str) -> str:
        """
        Compresses the input text using Gzip and returns a Base64 encoded string.
        :param text: The original text string.
        :return: A Base64 encoded string representing the Gzipped data.
        """
        byte_data = text.encode('utf-8')
        compressed_bytes = gzip.compress(byte_data)
        base64_bytes = base64.b64encode(compressed_bytes)
        base64_string = base64_bytes.decode('ascii')
        return base64_string

    def backward(self, text: str) -> str:
        """
        Decompresses the Base64 encoded Gzip data back into the original text.
        :param text: A Base64 encoded string representing Gzipped data.
        :return: The original text string.
        :raises ValueError: If the input string is not valid Base64 or not valid Gzip data.
        """
        try:
            base64_bytes = text.encode('ascii')
            compressed_bytes = base64.b64decode(base64_bytes)
            original_bytes = gzip.decompress(compressed_bytes)
            original_text = original_bytes.decode('utf-8')
            return original_text
        except (gzip.BadGzipFile, UnicodeDecodeError) as e:
            # Catch errors related to Base64 decoding, Gzip decompression, or UTF-8 decoding
            raise ValueError(f"Invalid input data for Gzip decompression: {e}") from e

    @property
    def static(self) -> bool:
        return False


