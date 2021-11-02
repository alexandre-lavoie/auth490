from .crypto import KeyHolder, PrivateKey
from .registry import Registry
from .data import DataType, DataRequest, DataTransfer
from .permissions import PermissionType
from typing import List

class Verifier:
    __registry: Registry
    __verifier: KeyHolder
    __private_key: PrivateKey
    __challenge: bytes

    def __init__(self, registry: Registry, verifier: KeyHolder, private_key: PrivateKey, challenge: bytes = None):
        self.__registry = registry
        self.__verifier = verifier
        self.__private_key = private_key
        self.__challenge = challenge

    def request_data(self, types: List[DataType]) -> DataRequest:
        request = DataRequest(
            requester=self.__verifier,
            types=types,
            challenge=self.__challenge
        )
        request.sign(self.__private_key)

        return request

    def validate_data(self, transfer: DataTransfer):
        if self.__challenge and not self.__challenge == transfer.challenge:
            raise Exception("Challenges do not match.")

        if not transfer.validate():
            raise Exception("Invalid tranfer signature.")

        for data in transfer.datas:
            if not self.__registry.has_permissions(data.provider, PermissionType.DATA_CREATION):
                raise Exception("Provider cannot create data.")
            if not data.recipient == transfer.provider:
                raise Exception("Data recipient does not match data provider.")
