from .crypto import Signable, KeyHolder, PublicKey, Signature
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

    def get_str_type(self) -> str:
        return "d"

    def serialize(self) -> any:
        return {
            "t": self.get_str_type().lower(), 
            "p": self.provider.serialize(), 
            "r": self.recipient.serialize(), 
            "v": self.value, 
            "d": self.type.value, 
            "s": self.signature.serialize()
        }

    @classmethod
    def deserialize(self, data: any) -> "Data":
        provider = KeyHolder.deserialize(data["p"])
        recipient = KeyHolder.deserialize(data["r"])
        value = data["v"]
        data_type = DataType(data["d"])

        _data = Data(
            provider,
            recipient,
            value,
            data_type
        )

        if 's' in data:
            signature = Signature.deserialize(data["s"])
            _data.signature = signature

        return _data

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

    def get_str_type(self) -> str:
        return "dt"

    def serialize(self) -> any:
        return {
            "t": self.get_str_type().lower(), 
            "p": self.provider.serialize(), 
            "d": [data.serialize() for data in self.datas], 
            "c": self.challenge, 
            "s": self.signature.serialize()
        }

    @classmethod
    def deserialize(self, data: any) -> "DataTransfer":
        provider = KeyHolder.deserialize(data["p"])
        datas = [Data.deserialize(d) for d in data["d"]]
        challenge = data["c"]

        data_transfer = DataTransfer(
            provider,
            datas,
            challenge
        )

        if 's' in data:
            siganture = Signature.deserialize(data["s"])
            data_transfer.signature = siganture

        return data_transfer

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

    def get_str_type(self) -> str:
        return "dr"

    def serialize(self) -> any:
        return {
            "t": self.get_str_type().lower(), 
            "r": self.requester.serialize(), 
            "d": [type.value for type in self.types], 
            "c": self.challenge, 
            "s": self.signature.serialize()
        }

    @classmethod
    def deserialize(self, data: any) -> "DataRequest":
        requester = KeyHolder.deserialize(data["r"])
        data_types = [DataType(d) for d in data["d"]]
        challenge = data["c"]

        data_request = DataRequest(
            requester,
            data_types,
            challenge
        ) 

        if 's' in data:
            signature = Signature.deserialize(data["s"])
            data_request.signature = signature

        return data_request

    def validate(self) -> bool:
        return self.requester.validate() and self._validate_signature(key=self.requester.key)

    def __str__(self) -> str:
        return f"DataRequest(requester={self.requester}, types={[type.name for type in self.types]}, challenge={self.challenge}, valid={self.validate()})"

    def __repr__(self) -> str:
        return str(self)
