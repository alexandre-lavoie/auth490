from .crypto import Signable, KeyHolder, PublicKey, Signature, PrivateKey
from .payload import Request, Payload
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

        if isinstance(provider.key, PrivateKey):
            self.sign(provider)

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

    @classmethod
    def get_type(cls) -> str:
        return "d"

    def raw_serialize(self) -> dict:
        return {
            **super().raw_serialize(),
            "p": self.provider.raw_serialize(), 
            "r": self.recipient.raw_serialize(), 
            "v": self.value, 
            "d": self.type.value
        }

    @classmethod
    def raw_deserialize(self, data: dict) -> "Data":
        _data = Data(
            provider=KeyHolder.raw_deserialize(data["p"]),
            recipient=KeyHolder.raw_deserialize(data["r"]),
            value=data["v"],
            type=DataType(data["d"])
        )
        _data.try_add_sign(data)

        return _data

    def validate(self) -> bool:
        return self._validate_signature(key=self.provider.key) and super().validate()

    def str_data(self) -> dict:
        return {
            "type": self.type.name,
            "value": self.value,
            "recipient": self.recipient,
            "provider": self.provider,
            **super().str_data()
        }

class DataTransfer(Payload):
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

    @classmethod
    def get_type(cls) -> str:
        return "dt"

    def raw_serialize(self) -> dict:
        return {
            **super().raw_serialize(),
            "p": self.provider.raw_serialize(), 
            "d": [data.raw_serialize() for data in self.datas], 
            "c": self.challenge
        }

    @classmethod
    def raw_deserialize(cls, data: dict) -> "DataTransfer":
        data_transfer = DataTransfer(
            provider=KeyHolder.raw_deserialize(data["p"]),
            datas=[Data.raw_deserialize(d) for d in data["d"]],
            challenge=data["c"]
        )
        data_transfer.try_add_sign(data)

        return data_transfer

    def validate(self) -> bool:
        return self.provider.validate() and all(data.validate() for data in self.datas) and self._validate_signature(key=self.provider.key)

    def str_data(self) -> dict:
        return {
            "challenge": self.challenge,
            **super().str_data()
        }

class DataRequest(Request):
    __requester: KeyHolder
    __types: List[DataType]
    __challenge: bytes

    def __init__(self, requester: KeyHolder, types: List[DataType], challenge: bytes = None):
        self.__types = types
        self.__challenge = challenge
        Request.__init__(self, requester)

    def get_value(self) -> List[DataType]:
        return self.__types

    @property
    def types(self) -> List[DataType]:
        return self.__types

    @property
    def challenge(self) -> bytes:
        return self.__challenge

    @classmethod
    def get_type(cls) -> str:
        return "dr"

    def raw_serialize(self) -> dict:
        return {
            **super().raw_serialize(),
            "c": self.challenge
        }

    @classmethod
    def raw_deserialize(self, data: dict) -> "DataRequest":
        data_request = DataRequest(
            requester=KeyHolder.raw_deserialize(data["r"]),
            types=[DataType(d) for d in data["d"]],
            challenge=data["c"]
        ) 
        data_request.try_add_sign(data)

        return data_request

    def str_data(self) -> dict:
        return {
            "challenge": self.challenge,
            **super().str_data()
        }
