from enum import Enum, auto
from .authority import Authority
from .crypto import Signable, KeyHolder, PublicKey, Signature
from typing import List

class PermissionType(Enum):
    AUTHORITY_APPROVAL=auto()
    PERMISSION_APPROVAL=auto()
    DATA_CREATION=auto()

class PermissionRequest(Signable):
    __requester: KeyHolder
    __permissions: List[PermissionType]

    def __init__(self, requester: KeyHolder, permissions: List[PermissionType]):
        self.__requester = requester
        self.__permissions = permissions

    @property
    def requester(self) -> KeyHolder:
        return self.__requester

    @property
    def permissions(self) -> List[PermissionType]:
        return self.__permissions

    def get_str_type(self) -> str:
        return "pr"

    def serialize(self) -> any:
        return {
            "t": self.get_str_type().lower(), 
            "r": self.requester.serialize(), 
            "p": [permission.value for permission in self.permissions], 
            "s": self.signature.serialize()
        }

    @classmethod
    def deserialize(cls, data: any) -> "PermissionRequest":
        requester = KeyHolder.deserialize(data["r"])
        permissions = [PermissionType(value) for value in data["p"]]

        request = PermissionRequest(
            requester,
            permissions
        )

        if 's' in data:
            signature = Signature.deserialize(data["s"])
            request.signature = signature

        return request

    def validate(self) -> bool:
        return self.requester.validate() and self._validate_signature(key=self.requester.key)

    def __str__(self) -> str:
        return f"PermissionRequest(requester={self.requester}, permissions={[permission.name for permission in self.permissions]}, valid={self.validate()})"

    def __repr__(self) -> str:
        return str(self)

class PermissionApproval(Signable):
    __approver: KeyHolder
    __permissions: List[PermissionType]
    __request: PermissionRequest

    def __init__(self, approver: KeyHolder, permissions: List[PermissionType], request: PermissionRequest):
        self.__approver = approver
        self.__permissions = permissions
        self.__request = request

    @property
    def approver(self) -> KeyHolder: 
        return self.__approver

    @property
    def permissions(self) -> List[PermissionType]:
        return self.__permissions

    @property
    def request(self) -> PermissionRequest:
        return self.__request

    def get_str_type(self) -> str:
        return "pa"

    def serialize(self) -> any:
        return {
            "t": self.get_str_type().lower(), 
            "a": self.approver.serialize(), 
            "p": [permission.value for permission in self.permissions], 
            "r": self.request.serialize(), 
            "s": self.signature.serialize()
        }

    @classmethod
    def deserialize(cls, data: any) -> "PermissionApproval":
        approver = KeyHolder.deserialize(data["a"])
        permissions = [PermissionType(value) for value in data["p"]]
        request = PermissionRequest.deserialize(data["r"])

        approval = PermissionApproval(
            approver,
            permissions,
            request
        )

        if 's' in data:
            signature = Signature.deserialize(data["s"])
            approval.signature = signature

        return approval

    def validate(self) -> bool:
        return self.approver.validate() and self.request.validate() and self._validate_signature(key=self.approver.key)

    def __str__(self) -> str:
        return f"PermissionApproval(entity={self.request.requester}, permissions={[permission.name for permission in self.permissions]}, approver={self.approver}, valid={self.validate()})"

    def __repr__(self) -> str:
        return str(self)
