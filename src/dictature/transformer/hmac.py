import hmac
from hashlib import sha256
from .mock import MockTransformer


class HmacTransformer(MockTransformer):
    def __init__(self, secret: str = 'dictature') -> None:
        """
        Perform HMAC on the text.
        :param secret: secret key to use for HMAC, if not provided works as a simple hash function
        """
        self.__secret = secret

    def forward(self, text: str) -> str:
        return f"{self.__hmac(text)}-{text}"

    def backward(self, text: str) -> str:
        mac, text = text.split('-', 1)
        if mac != self.__hmac(text):
            raise ValueError('Invalid HMAC')
        return text

    def __hmac(self, text: str) -> str:
        return hmac.new(self.__secret.encode('utf8'), text.encode('utf8'), sha256).hexdigest()

    @property
    def static(self) -> bool:
        return True
