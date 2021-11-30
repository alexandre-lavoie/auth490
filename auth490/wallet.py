from .serialize import Serializable, deserialize
from .crypto import PrivateKey, PublicKey, Signable
from .data import Data
from typing import List
from flask import Request, Response
import base64

class Wallet(Signable):
    __data: List[Serializable]

    def __init__(self, data: List[Serializable] = None):
        if data:
            self.__data = data
        else:
            self.__data = []

    @classmethod
    def get_type(self) -> str:
        return "w"

    def raw_serialize(self) -> dict:
        return {
            **super().raw_serialize(),
            "d": [d.serialize() for d in self.__data]
        }

    @classmethod
    def raw_deserialize(self, data: dict) -> "Wallet":
        wallet = Wallet(
            data=[deserialize(d) for d in data["d"]]
        )
        wallet.try_add_sign(data)

        return wallet

    def validate(self) -> bool:
        # TODO: Sign wallet?
        return True

    def insert(self, data: Serializable):
        if not isinstance(data, PrivateKey) and not isinstance(data, PublicKey) and not isinstance(data, Data):
            raise Exception("Cannot store class to wallet.")

        self.__data.append(data)

    def remove(self, index: int):
        del self.__data[index]

    @property
    def values(self):
        return self.__data

    @property
    def data(self):
        return [data for data in self.__data if isinstance(data, Data)]

    @property
    def private_keys(self):
        return [data for data in self.__data if isinstance(data, PrivateKey)]

    @classmethod
    def load(cls, request: Request) -> "Wallet":
        if not "wallet" in request.cookies or len(request.cookies["wallet"].strip()) == 0:
            return Wallet()

        return Wallet.deserialize(request.cookies["wallet"])

    def dump(self, response: Response) -> Response:
        response.set_cookie(f"wallet", self.serialize())

        return response

    def str_data(self) -> dict:
        return {
            "data": self.__data,
            **super().str_data()
        }
