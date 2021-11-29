from auth490.serialize import Serializable, deserialize
from auth490.crypto import PrivateKey
from auth490.data import Data
from typing import List
from flask import Request, Response
import base64

class Wallet:
    __data: List[Serializable]

    def __init__(self, data: List[Serializable] = None):
        if data:
            self.__data = data
        else:
            self.__data = []

    def add(self, data: Serializable):
        if not isinstance(data, PrivateKey) or not isinstance(data, Data):
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

        b64_data = request.cookies["wallet"]
        str_data = base64.urlsafe_b64decode(b64_data.encode()).decode().split(",")
        data = [deserialize(sd) for sd in str_data]

        return Wallet(data)

    def dump(self, response: Response):
        qr_data = [d.qr_serialize() for d in self.__data]
        data = ','.join(qr_data)
        cookie = base64.urlsafe_b64encode(data.encode()).decode()

        response.set_cookie(f"wallet", cookie)

        return response
