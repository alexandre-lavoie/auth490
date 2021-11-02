from .crypto import Signable, KeyHolder, PublicKey
from enum import Enum, auto
from typing import List

class DataType(Enum):
    NAME=auto()
    VACCINE=auto()

class Data(Signable):
    __provider: KeyHolder
    __recipient: KeyHolder
    __value: str
    __type: DataType

    def __init__(self, provider: KeyHolder, recipient: KeyHolder, value: str, type: DataType):
        self.__provider = provider
        self.__recipient = recipient
        self.__value = value
        self.__type = type

    @property
    def provider(self) -> KeyHolder:
        return self.__provider

    @property
    def recipient(self) -> KeyHolder:
        return self.__recipient

    @property
    def value(self) -> str:
        return self.__value

    @property
    def type(self) -> DataType:
        return self.__type

    def serialize(self) -> any:
        return {"p": self.provider.serialize(), "r": self.recipient.serialize(), "v": self.value, "t": self.type.value, "s": self.signature.serialize()}

    def validate(self) -> bool:
        return self._validate_signature(key=self.provider.key)

    def __str__(self) -> str:
        return f"Data(type={self.type.name}, value={self.value}, recipient={self.recipient}, provider={self.provider}, valid={self.validate()})"

    def __repr__(self) -> str:
        return str(self)

class DataTransfer(Signable):
    __provider: KeyHolder
    __datas: List[Data]
    __challenge: str

    def __init__(self, provider: KeyHolder, datas: List[Data], challenge: str = None):
        self.__provider = provider
        self.__datas = datas
        self.__challenge = challenge

    @property
    def provider(self) -> KeyHolder:
        return self.__provider

    @property
    def datas(self) -> List[Data]:
        return self.__datas

    @property
    def challenge(self) -> bytes:
        return self.__challenge

    def serialize(self) -> any:
        return {"p": self.provider.serialize(), "d": [data.serialize() for data in self.datas], "c": self.challenge, "s": self.signature.serialize()}

    def validate(self) -> bool:
        return self.provider.validate() and all(data.validate() for data in self.datas) and self._validate_signature(key=self.provider.key)

    def __str__(self) -> str:
        return f"DataTransfer(provider={self.provider}, datas={self.datas}, challenge={self.challenge}, valid={self.validate()})"

    def __repr__(self) -> str:
        return str(self)

class DataRequest(Signable):
    __requester: KeyHolder
    __types: List[DataType]
    __challenge: bytes

    def __init__(self, requester: KeyHolder, types: List[DataType], challenge: bytes = None):
        self.__requester = requester
        self.__types = types
        self.__challenge = challenge

    @property
    def requester(self) -> KeyHolder:
        return self.__requester

    @property
    def types(self) -> List[DataType]:
        return self.__types

    @property
    def challenge(self) -> bytes:
        return self.__challenge

    def serialize(self) -> any:
        return {"r": self.requester.serialize(), "t": [type.value for type in self.types], "c": self.challenge, "s": self.signature.serialize()}

    def validate(self) -> bool:
        return self.requester.validate() and self._validate_signature(key=self.requester.key)

    def __str__(self) -> str:
        return f"DataRequest(requester={self.requester}, types={[type.name for type in self.types]}, challenge={self.challenge}, valid={self.validate()})"

    def __repr__(self) -> str:
        return str(self)
