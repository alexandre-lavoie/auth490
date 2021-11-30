from enum import Enum, auto
from typing import List

from .authority import Authority
from .payload import Request, Approval
from .crypto import Signable, KeyHolder, PublicKey, Signature

class PermissionType(Enum):
    AUTHORITY_APPROVAL=auto()
    PERMISSION_APPROVAL=auto()
    DATA_CREATION=auto()

class PermissionRequest(Request):
    __permissions: List[PermissionType]

    def __init__(self, requester: KeyHolder, permissions: List[PermissionType]):
        self.__permissions = permissions
        Request.__init__(self, requester)

    def get_value(self) -> List[int]:
        return [v.value for v in self.__permissions]

    @property
    def permissions(self) -> List[PermissionType]:
        return self.__permissions

    @classmethod
    def get_type(cls) -> str:
        return "pr"

    @classmethod
    def raw_deserialize(cls, data: dict) -> "PermissionRequest":
        request = PermissionRequest(
            requester=KeyHolder.raw_deserialize(data["r"]),
            permissions=[PermissionType(value) for value in data["d"]]
        )
        request.try_add_sign(data)

        return request

class PermissionApproval(Approval):
    __permissions: List[PermissionType]
    __request: PermissionRequest

    def __init__(self, approver: KeyHolder, permissions: List[PermissionType], request: PermissionRequest):
        self.__permissions = permissions
        self.__request = request
        Approval.__init__(self, approver)

    def get_request(self) -> PermissionRequest:
        return self.__request 

    @property
    def permissions(self) -> List[PermissionType]:
        return self.__permissions

    @classmethod
    def get_type(cls) -> str:
        return "pa"

    def raw_serialize(self) -> dict:
        return {
            **super().raw_serialize(),
            "p": [permission.value for permission in self.permissions]
        }

    @classmethod
    def raw_deserialize(cls, data: dict) -> "PermissionApproval":
        approval = PermissionApproval(
            approver=KeyHolder.raw_deserialize(data["a"]),
            permissions=[PermissionType(value) for value in data["p"]],
            request=PermissionRequest.raw_deserialize(data["r"])
        )
        approval.try_add_sign(data)

        return approval
