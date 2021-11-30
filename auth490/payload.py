from .crypto import KeyHolder, Signable, PrivateKey
from .serialize import Serializable
from abc import ABC, abstractmethod

class Payload(Signable, ABC):
    pass

class Request(Payload, ABC):
    _requester: KeyHolder

    def __init__(self, requester: KeyHolder):
        self._requester = requester

        if isinstance(requester.key, PrivateKey):
            self.sign(requester)

    @property
    def requester(self) -> KeyHolder:
        return self._requester

    @abstractmethod
    def get_value(self) -> Serializable:
        pass

    def validate(self) -> bool:
        return self.requester.validate() and self._validate_signature(self.requester)

    def raw_serialize(self) -> dict:
        value = self.get_value()
        if isinstance(value, list):
            value = [v.raw_serialize() if isinstance(v, Serializable) else v for v in value]
        elif isinstance(value, Serializable):
            value = value.raw_serialize()

        return {
            **super().raw_serialize(),
            "d": value,
            "r": self.requester.raw_serialize()
        }

    def str_data(self) -> dict:
        return {
            "requester": self._requester,
            "data": self.get_value(),
            **super().str_data()
        }

class Approval(Payload, ABC):
    _approver: KeyHolder

    def __init__(self, approver: KeyHolder):
        self._approver = approver

        if isinstance(approver.key, PrivateKey):
            self.sign(approver)

    @property
    def approver(self) -> KeyHolder:
        return self._approver

    @abstractmethod
    def get_request() -> Request:
        pass

    def validate(self) -> bool:
        return self.approver.validate() and self._validate_signature(self.approver)

    def raw_serialize(self) -> dict:
        return {
            **super().raw_serialize(),
            "r": self.get_request().raw_serialize(),
            "a": self.approver.raw_serialize()
        }

    def str_data(self) -> dict:
        return {
            "approver": self._approver,
            "request": self.get_request(),
            **super().str_data()
        }
