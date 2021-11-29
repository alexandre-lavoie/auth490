from dataclasses import dataclass
import base64
import json
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from abc import ABC, abstractmethod, abstractclassmethod
from typing import Union
import zlib
import re
from .serialize import Serializable

class Signature:
    __value: bytes

    def __init__(self, value: bytes = None):
        self.__value = value

    def to_base64(self) -> str:
        if self.__value == None:
            return ""

        return base64.urlsafe_b64encode(self.__value).decode()

    @property
    def raw(self) -> bytes:
        return self.__value

    def serialize(self) -> any:
        return self.to_base64()

    @classmethod
    def deserialize(self, data: any) -> 'Signature':
        return Signature(
            value=base64.urlsafe_b64decode(data)
        )

    def __str__(self):
        return f"Signature(value={self.to_base64()})"

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other: any) -> bool:
        if not isinstance(other, Signature): return False

        return self.__value == other.__value

class PublicKey(Serializable):
    __public_key: any

    def __init__(self, public_key: any):
        self.__public_key = public_key

    def get_str_type(self) -> str:
        return "k"

    def to_base64(self) -> str:
        n = self.__public_key.n.to_bytes(128, byteorder='big')

        return base64.urlsafe_b64encode(n).decode()

    def to_short_base64(self) -> str:
        n = self.__public_key.n.to_bytes(128, byteorder='big')

        return base64.urlsafe_b64encode(n[:32]).decode()

    def serialize(self) -> any:
        return self.to_base64()

    @classmethod
    def deserialize(cls, data: str) -> 'PublicKey':
        n = int.from_bytes(base64.urlsafe_b64decode(data), byteorder='big')
        
        public_key = RSA.construct((n, 65537))

        return PublicKey(
            public_key=public_key
        )

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

class PrivateKey(Serializable):
    __key_pair: any

    def __init__(self, key_pair: any):
        self.__key_pair = key_pair

    def get_str_type(self) -> str:
        return "pk"

    @classmethod
    def generate(cls) -> "PrivateKey":
        key_pair = RSA.generate(1024)

        return PrivateKey(
            key_pair=key_pair
        )

    @property
    def public_key(self) -> PublicKey:
        return PublicKey(
            public_key=self.__key_pair.public_key()
        )

    def to_base64(self) -> str:
        n = self.__key_pair.n.to_bytes(128, byteorder='big')
        d = self.__key_pair.d.to_bytes(128, byteorder='big')

        return base64.urlsafe_b64encode(n + d).decode()

    def serialize(self) -> any:
        return self.to_base64()

    @classmethod
    def deserialize(cls, data: str):
        b = base64.urlsafe_b64decode(data)

        n = int.from_bytes(b[:128], byteorder='big')
        d = int.from_bytes(b[128:], byteorder='big')

        private_key = RSA.construct((n, 65537, d))

        return PrivateKey(
            key_pair=private_key
        )

    def sign(self, data: bytes) -> Signature:
        signed_data = pkcs1_15.new(self.__key_pair).sign(SHA256.new(data))

        return Signature(signed_data)

    def validate(self, data: bytes, signature: Signature) -> bool:
        try:
            pkcs1_15.new(self.__key_pair).verify(SHA256.new(data), signature.raw)
            return True
        except (ValueError, TypeError):
            return False

    def __str__(self):
        return f"PrivateKey(n={self.__key_pair.n}, d={self.__key_pair.d})"

    def __eq__(self, other: any) -> bool:
        if not isinstance(other, PrivateKey): return False

        return self.to_base64() == other.to_base64()

class Signable(Serializable, ABC):
    signature: Signature = Signature()

    @abstractmethod
    def validate(self) -> bool:
        return False

    def sign(self, key: PrivateKey) -> Signature:
        self.signature = key.sign(self.b64_serialize(with_signature=False).encode())

        return self.signature

    def _validate_signature(self, key: PublicKey) -> bool:
        if not self.signature: return False

        return key.validate(self.b64_serialize(with_signature=False).encode(), self.signature)

class KeyHolder:
    __key: Union[PublicKey, PrivateKey]

    def __init__(self, key: Union[PublicKey, PrivateKey]):
        self.__key = key

    @property
    def key(self) -> Union[PublicKey, PrivateKey]:
        return self.__key

    @classmethod
    def deserialize(self, data: any) -> any:
        if data["t"] == "a":
            from .authority import Authority
            return Authority.deserialize(data)
        elif data["t"] == "u":
            from .people import Person
            return Person.deserialize(data)
        else:
            raise Exception("Unknown KeyHolder " + data["t"])
