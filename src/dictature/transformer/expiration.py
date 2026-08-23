from __future__ import annotations

from time import time
from typing import Union
from .mock import MockTransformer


class ExpirationTransformer(MockTransformer):
    def __init__(self, expiration_time: Union[float, int]):
        """
        Creates a new ExpirationTransformer.

        :param expiration_time: how many seconds before the values are considered expired
        """
        self.__expiration_time = expiration_time

    def forward(self, text: str) -> str:
        """
        Adds expiration timestamp to the text.

        :param text: original text
        :return: text prefixed with ``<expiry_timestamp>-``
        """
        expiration_timestamp = time() + self.__expiration_time
        return f"{expiration_timestamp}-{text}"

    def backward(self, text: str) -> str:
        """
        Strips the expiration timestamp and checks whether the value has expired.

        :param text: stored text produced by ``forward``
        :return: original text
        :raises KeyError: if the value's TTL has elapsed
        """
        expiration_timestamp, original_text = text.split('-', 1)
        if time() > float(expiration_timestamp):
            raise KeyError('Value is expired')
        return original_text

    @property
    def static(self) -> bool:
        """
        Returns False because ``forward`` always embeds the current time, making each result unique.
        """
        return False
