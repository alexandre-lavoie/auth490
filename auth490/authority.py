from typing import Union

from .people import Person
from .crypto import KeyHolder, Signable, Signature, PublicKey

class Authority(Signable, KeyHolder):
    __name: str

    def __init__(self, name: str, key: PublicKey):
        KeyHolder.__init__(self, key=key)
        self.__name = name

    @property
    def name(self) -> str:
        return self.__name

    def get_str_type(self) -> str:
        return "a"

    def serialize(self) -> any:
        return {
            "t": self.get_str_type().lower(), 
            "k": self.key.serialize(), 
            "n": self.name, 
            "s": self.signature.serialize()
        }

    @classmethod
    def deserialize(self, data: any) -> 'Authority':
        authority = Authority(
            name=data['n'],
            key=PublicKey.deserialize(data['k'])
        )

        if 's' in data: 
            signature = Signature.deserialize(data['s'])
            authority.signature = signature

        return authority

    def validate(self) -> bool:
        return self._validate_signature(key=self.key)

    def __str__(self) -> str:
        return f"Authority(name={self.name}, valid={self.validate()})"

    def __repr__(self) -> str:
        return str(self)

    def __eq__(self, other: any) -> bool:
        if not isinstance(other, Authority): return False

        if not self.signature == other.signature:
            return False

        return self.key == other.key 

class AuthorityRequest(Signable):
    __requester: KeyHolder
    __authority: Authority

    def __init__(self, requester: KeyHolder, authority: Authority):
        self.__requester = requester
        self.__authority = authority

    @property
    def requester(self) -> KeyHolder:
        return self.__requester

    @property
    def authority(self) -> Authority:
        return self.__authority

    def get_str_type(self) -> str:
        return "ar"

    def serialize(self) -> any:
        return {
            "t": self.get_str_type().lower(), 
            "r": self.requester.serialize(), 
            "a": self.authority.serialize(), 
            "s": self.signature.serialize()
        }

    @classmethod
    def deserialize(cls, data: any) -> "AuthorityRequest":
        requester = KeyHolder.deserialize(data["r"])
        authority = Authority.deserialize(data["a"])

        request = AuthorityRequest(
            requester=requester,
            authority=authority
        )

        if 's' in data:
            signature = Signature.deserialize(data["s"])
            request.signature = signature

        return request

    def validate(self) -> bool:
        return self.requester.validate() and self.authority.validate() and self._validate_signature(key=self.requester.key)

    def __str__(self) -> str:
        return f"AuthorityRequest(authority={self.authority}, requester={self.requester}, valid={self.validate()})"

    def __repr__(self) -> str:
        return str(self)

class AuthorityApproval(Signable):
    __approver: KeyHolder
    __request: AuthorityRequest

    def __init__(self, approver: KeyHolder, request: AuthorityRequest):
        self.__approver = approver
        self.__request = request

    @property
    def approver(self) -> KeyHolder:
        return self.__approver

    @property
    def request(self) -> AuthorityRequest:
        return self.__request

    def get_str_type(self) -> str:
        return "aa"

    def serialize(self) -> any:
        return {
            "t": self.get_str_type().lower(), 
            "a": self.approver.serialize(), 
            "r": self.request.serialize(), 
            "s": self.signature.serialize()
        }

    @classmethod
    def deserialize(cls, data: any) -> "AuthorityApproval":
        approver = KeyHolder.deserialize(data["a"])
        request = AuthorityRequest.deserialize(data["r"])

        approval = AuthorityApproval(
            approver=approver,
            request=request
        )

        if 's' in data:
            signature = Signature.deserialize(data["s"])
            approval.signature = signature

        return approval

    def validate(self) -> bool:
        return self.approver.validate() and self.request.validate() and self._validate_signature(key=self.approver.key)

    def __str__(self) -> str:
        return f"AuthorityApproval(authority={self.request.authority}, approver={self.approver}, valid={self.validate()})"

    def __repr__(self) -> str:
        return str(self)
