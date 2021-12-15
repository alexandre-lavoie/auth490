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
from .serialize import Serializable, cls_deserialize
from typing import Union

class Signature(Serializable):
    __value: bytes

    def __init__(self, value: bytes = None):
        self.__value = value

    def to_b64(self) -> str:
        if self.__value == None:
            return ""

        return base64.urlsafe_b64encode(self.__value).decode()

    @classmethod
    def get_type(cls) -> str:
        return "s"

    @property
    def raw(self) -> bytes:
        return self.__value

    def raw_serialize(self) -> dict:
        return self.to_b64()

    @classmethod
    def raw_deserialize(self, data: dict) -> 'Signature':
        return Signature(
            value=base64.urlsafe_b64decode(data)
        )

    def str_data(self) -> dict:
        return {
            "value": self.to_b64(),
            **super().str_data()
        }

    def __eq__(self, other: any) -> bool:
        if not isinstance(other, Signature): return False

        return self.__value == other.__value

class Validator(ABC):
    @abstractmethod
    def get_validate(self, data: bytes, signature: Signature) -> bool:
        return True

class Key(Serializable, Validator, ABC):
    @abstractmethod
    def to_b64(self) -> str:
        pass

    def raw_serialize(self) -> dict:
        return self.to_b64()

    @property
    @abstractmethod
    def public_key(self) -> "PublicKey":
        pass

    def __eq__(self, other: any) -> bool:
        if not isinstance(other.public_key, self.public_key.__class__): 
            return False

        return self.public_key.to_b64() == other.public_key.to_b64()

class PublicKey(Key, ABC):
    @classmethod
    def get_type(cls) -> str:
        return "k"

    @classmethod
    def raw_deserialize(cls, data: dict) -> "PublicKey":
        # TODO: Check key type.
        return RSAPublicKey.raw_deserialize(data)

    @property
    def public_key(self) -> "PublicKey":
        return self

class RSAPublicKey(PublicKey):
    __public_key: any

    def __init__(self, public_key: any):
        self.__public_key = public_key

    def to_b64(self) -> str:
        n = self.__public_key.n.to_bytes(128, byteorder='big')

        return base64.urlsafe_b64encode(n).decode()

    @classmethod
    def raw_deserialize(cls, data: dict) -> 'RSAPublicKey':
        n = int.from_bytes(base64.urlsafe_b64decode(data), byteorder='big')
        
        public_key = RSA.construct((n, 65537))

        return RSAPublicKey(
            public_key=public_key
        )

    def get_validate(self, data: bytes, signature: Signature) -> bool:
        if data == None or signature == None:
            return False

        try:
            pkcs1_15.new(self.__public_key).verify(SHA256.new(data), signature.raw)
            return True
        except (ValueError, TypeError):
            return False

    def str_data(self) -> dict:
        return {
            "n": self.__public_key.n,
            **super().str_data()
        }

class Signer(Validator, ABC):
    @abstractmethod
    def get_sign(self, data: bytes) -> Signature:
        pass

class PrivateKey(Key, Signer, ABC):
    @classmethod
    def get_type(cls) -> str:
        return "pk"

    @abstractclassmethod
    def generate(cls) -> "PrivateKey":
        pass

    @classmethod
    def raw_deserialize(cls, data: dict) -> "PrivateKey":
        # TODO: Check key type.
        return RSAPrivateKey.raw_deserialize(data)

    def get_validate(self, data: bytes, signature: Signature) -> bool:
        return self.public_key.get_validate(data, signature)

class RSAPrivateKey(PrivateKey):
    __key_pair: any

    def __init__(self, key_pair: any):
        self.__key_pair = key_pair

    @classmethod
    def generate(cls) -> "RSAPrivateKey":
        return RSAPrivateKey(
            key_pair=RSA.generate(1024)
        )

    @property
    def public_key(self) -> RSAPublicKey:
        return RSAPublicKey(
            public_key=self.__key_pair.public_key()
        )

    def to_b64(self) -> str:
        n = self.__key_pair.n.to_bytes(128, byteorder='big')
        d = self.__key_pair.d.to_bytes(128, byteorder='big')

        return base64.urlsafe_b64encode(n + d).decode()

    @classmethod
    def raw_deserialize(cls, data: dict) -> "RSAPrivateKey":
        b = base64.urlsafe_b64decode(data)

        n = int.from_bytes(b[:128], byteorder='big')
        d = int.from_bytes(b[128:], byteorder='big')

        private_key = RSA.construct((n, 65537, d))

        return RSAPrivateKey(
            key_pair=private_key
        )

    def get_sign(self, data: Union[str, bytes]) -> Signature:
        if isinstance(data, str):
            data = data.encode()

        signed_data = pkcs1_15.new(self.__key_pair).sign(SHA256.new(data))

        return Signature(signed_data)

    def str_data(self) -> dict:
        return {
            "n": self.__key_pair.n,
            "d": self.__key_pair.d,
            **super().str_data()
        }

class Signable(Serializable, ABC):
    signature: Signature = Signature()

    @abstractmethod
    def validate(self) -> bool:
        return True

    def raw_serialize(self) -> dict:
        return {
            **super().raw_serialize(),
            "s": self.signature.raw_serialize()
        }

    def try_add_sign(self, data: any):
        if isinstance(data, dict):
            if 's' in data:
                signature = Signature.raw_deserialize(data['s'])
                self.signature = signature
        elif isinstance(data, Signature):
            self.signature = data

    def is_signed(self) -> bool:
        return not self.signature == None and not self.signature.raw == None and len(self.signature.raw) > 0

    def sign(self, signer: Signer) -> Signature:
        self.signature = signer.get_sign(self.b64_serialize(with_signature=False))
        return self.signature

    def _validate_signature(self, key: Validator) -> bool:
        return key.get_validate(self.b64_serialize(with_signature=False).encode(), self.signature)

    def str_data(self) -> dict:
        return {
            # "signed": self.is_signed(),
            # "valid": self.validate(),
            **super().str_data()
        }

class KeyHolder(Signer, Signable, ABC):
    __key: Union[PublicKey, PrivateKey]

    def __init__(self, key: Union[PublicKey, PrivateKey]):
        self.__key = key

        if isinstance(key, PrivateKey):
            self.sign(key)

    def validate(self) -> bool:
        return self._validate_signature(self.__key)

    def is_private(self) -> bool:
        return isinstance(self.__key, PrivateKey)

    def raw_serialize(self) -> dict:
        return {
            **super().raw_serialize(),
            "k": self.__key.public_key.raw_serialize()
        }

    def get_sign(self, data: bytes) -> Signature:
        if isinstance(self.__key, PublicKey):
            raise Exception("Cannot sign with a public key.")

        return self.__key.get_sign(data)

    def get_validate(self, data: bytes, signature: Signature):
        return self.__key.get_validate(data, signature)

    @property
    def public_key(self) -> PublicKey:
        return self.__key.public_key

    @property
    def key(self) -> Union[PublicKey, PrivateKey]:
        return self.__key

    @classmethod
    def raw_deserialize(self, data: dict) -> "KeyHolder":
        result = cls_deserialize(KeyHolder, data)

        if not result:
            raise Exception("Unknown KeyHolder " + data["t"])

        return result

    def __eq__(self, other: any) -> bool:
        if not isinstance(other, self.__class__): 
            return False

        if not self.signature == other.signature:
            return False

        return self.key == other.key

    def str_data(self) -> dict:
        return {
            # "private": self.is_private(),
            **super().str_data()
        }
