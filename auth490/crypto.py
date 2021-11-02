from dataclasses import dataclass
import base64
import json
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from abc import ABC, abstractmethod
from typing import Union
import zlib

class Signature:
    __value: bytes

    def __init__(self, value: bytes = None):
        self.__value = value

    def to_base64(self) -> str:
        if self.__value == None:
            return ""

        return base64.b64encode(self.__value).decode()

    @property
    def raw(self) -> bytes:
        return self.__value

    def serialize(self) -> any:
        return self.to_base64()

    def __str__(self):
        return f"Signature(value={self.to_base64()})"

    def __repr__(self):
        return self.__str__()

class PublicKey:
    __public_key: any

    def __init__(self, public_key: any):
        self.__public_key = public_key

    def to_base64(self) -> str:
        return base64.urlsafe_b64encode(self.__public_key.n.to_bytes(128, byteorder='big')).decode()

    def to_short_base64(self) -> str:
        return base64.urlsafe_b64encode(self.__public_key.n.to_bytes(128, byteorder='big')[:32]).decode()

    def serialize(self) -> any:
        return self.to_base64()

    def validate(self, data: bytes, signature: Signature) -> bool:
        try:
            pkcs1_15.new(self.__public_key).verify(SHA256.new(data), signature.raw)
            return True
        except (ValueError, TypeError):
            return False

    def __str__(self):
        return f"PublicKey(n={self.__public_key.n})"

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other: any) -> bool:
        if not isinstance(other, PublicKey): return False

        return self.to_base64() == other.to_base64()

class PrivateKey:
    __key_pair: any

    def __init__(self, key_pair: any):
        self.__key_pair = key_pair

    @classmethod
    def generate(cls) -> "PrivateKey":
        key_pair = RSA.generate(1024)

        return PrivateKey(
            key_pair=key_pair
        )

    @property
    def public_key(self) -> PublicKey:
        return PublicKey(public_key=self.__key_pair.public_key())

    def to_base64(self) -> str:
        return self.public_key.to_base64()

    def to_short_base64(self) -> str:
        return self.public_key.to_short_base64()
    
    def serialize(self) -> any:
        return self.to_base64()

    def sign(self, data: bytes) -> Signature:
        signed_data = pkcs1_15.new(self.__key_pair).sign(SHA256.new(data))

        return Signature(signed_data)

    def validate(self, data: bytes, signature: Signature) -> bool:
        try:
            pkcs1_15.new(self.__key_pair).verify(SHA256.new(data), signature.raw)
            return True
        except (ValueError, TypeError):
            return False

    def __eq__(self, other: any) -> bool:
        if not isinstance(other, PrivateKey): return False

        return self.to_base64() == other.to_base64()

class Signable(ABC):
    signature: Signature = Signature()

    @abstractmethod
    def serialize(self) -> any:
        return None

    @abstractmethod
    def validate(self) -> bool:
        return False

    def b64_serialize(self) -> str:
        serialized_data = self.serialize()
        del serialized_data["s"]
        dumped_data = json.dumps(serialized_data, separators=(',', ':')).encode()
        compressed_data = zlib.compress(dumped_data)
        b64_data = base64.urlsafe_b64encode(compressed_data).decode()

        return b64_data

    def qr_serialize(self) -> str:
        data = self.b64_serialize()
        mapped_data = ''.join(str(ord(c) - 45) for c in data)

        return mapped_data

    def sign(self, key: PrivateKey) -> Signature:
        self.signature = key.sign(self.b64_serialize().encode())

        return self.signature

    def _validate_signature(self, key: PublicKey) -> bool:
        if not self.signature: return False

        return key.validate(self.b64_serialize().encode(), self.signature)

class KeyHolder:
    __key: Union[PublicKey, PrivateKey]

    def __init__(self, key: Union[PublicKey, PrivateKey]):
        self.__key = key

    @property
    def key(self) -> Union[PublicKey, PrivateKey]:
        return self.__key
