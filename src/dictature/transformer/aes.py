from typing import Callable, Optional

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Protocol.KDF import scrypt
except ImportError:
    raise ImportError("PyCryptodome is required to use this module -- pip install pycryptodome")

from .mock import MockTransformer


class AESTransformer(MockTransformer):
    def __init__(
            self,
            passphrase: str,
            static_names_mode: bool,
            salt: str = 'dictature',
            bytes_encoder: Optional[Callable[[bytes], str]] = None,
            bytes_decoder: Optional[Callable[[str], bytes]] = None
    ) -> None:
        """
        Create a new AES transformer
        :param passphrase: secret passphrase to encrypt/decrypt the data
        :param static_names_mode: if True, the transformer will use ECB mode instead of GCM (True decreases security, increases speed)
        :param salt: salt to use for the key derivation
        :param bytes_encoder: function to encode bytes to string, can be e.g. b64encode (default: hex)
        :param bytes_decoder: function to decode string to bytes, can be e.g. b64decode (default: hex)
        """
        self.__key = scrypt(passphrase, salt, 16, N=2 ** 14, r=8, p=1)
        self.__mode = AES.MODE_GCM if not static_names_mode else AES.MODE_ECB
        self.__static = static_names_mode
        self.__bytes_encoder = bytes_encoder if bytes_encoder else (lambda b: b.hex())
        self.__bytes_decoder = bytes_decoder if bytes_decoder else (lambda s: bytes.fromhex(s))

    def forward(self, text: str) -> str:
        cipher = self.__cipher()
        if self.__mode == AES.MODE_GCM:
            ciphertext, tag = cipher.encrypt_and_digest(pad(text.encode('utf8'), AES.block_size))
            data = (cipher.nonce + tag + ciphertext)
        else:
            data = cipher.encrypt(pad(text.encode('utf8'), AES.block_size))

        return self.__bytes_encoder(data)

    def backward(self, text: str) -> str:
        data = self.__bytes_decoder(text)
        if self.__mode == AES.MODE_GCM:
            nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
            return unpad(self.__cipher(nonce=nonce).decrypt_and_verify(ciphertext, tag), AES.block_size).decode('utf8')
        else:
            return unpad(self.__cipher().decrypt(data), AES.block_size).decode('utf8')

    def __cipher(self, **kwargs) -> AES:
        # noinspection PyTypeChecker
        return AES.new(self.__key, self.__mode, **kwargs)

    @property
    def static(self) -> bool:
        return self.__static
