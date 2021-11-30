from typing import Union

from .payload import Request, Approval
from .crypto import KeyHolder, Signable, Signature, PublicKey

class Authority(KeyHolder):
    __name: str

    def __init__(self, name: str, key: PublicKey):
        self.__name = name
        KeyHolder.__init__(self, key=key)

    @property
    def name(self) -> str:
        return self.__name

    @classmethod
    def get_type(cls) -> str:
        return "a"

    def raw_serialize(self) -> dict:
        return {
            **super().raw_serialize(),
            "n": self.name
        }

    @classmethod
    def raw_deserialize(self, data: dict) -> 'Authority':
        authority = Authority(
            name=data['n'],
            key=PublicKey.raw_deserialize(data['k'])
        )
        authority.try_add_sign(data)

        return authority

    def str_data(self) -> dict:
        return {
            "name": self.name,
            **super().str_data()
        }

class AuthorityRequest(Request):
    __authority: Authority

    def __init__(self, requester: KeyHolder, authority: Authority):
        self.__authority = authority
        Request.__init__(self, requester)

    def get_value(self) -> Authority:
        return self.__authority

    @property
    def authority(self) -> Authority:
        return self.__authority

    @classmethod
    def get_type(cls) -> str:
        return "ar"

    @classmethod
    def raw_deserialize(cls, data: dict) -> "AuthorityRequest":
        request = AuthorityRequest(
            requester=KeyHolder.raw_deserialize(data["r"]),
            authority=Authority.raw_deserialize(data["d"])
        )
        request.try_add_sign(data)

        return request

    def validate(self) -> bool:
        return self.authority.validate() and super().validate()

class AuthorityApproval(Approval):
    __request: AuthorityRequest

    def __init__(self, approver: KeyHolder, request: AuthorityRequest):
        self.__request = request
        Approval.__init__(self, approver)

    def get_request(self) -> AuthorityRequest:
        return self.__request

    @classmethod
    def get_type(cls) -> str:
        return "aa"

    @classmethod
    def raw_deserialize(cls, data: dict) -> "AuthorityApproval":
        approval = AuthorityApproval(
            approver=KeyHolder.raw_deserialize(data["a"]),
            request=AuthorityRequest.raw_deserialize(data["r"])
        )
        approval.try_add_sign(data)

        return approval
