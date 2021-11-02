from typing import Union

from .people import Person
from .crypto import KeyHolder, Signable, PublicKey

class Authority(Signable, KeyHolder):
    __name: str

    def __init__(self, name: str, key: PublicKey):
        KeyHolder.__init__(self, key=key)
        self.__name = name

    @property
    def name(self) -> str:
        return self.__name

    def serialize(self) -> any:
        return {"k": self.key.serialize(), "n": self.name, "s": self.signature.serialize()}

    def validate(self) -> bool:
        return self._validate_signature(key=self.key)

    def __str__(self) -> str:
        return f"Authority(name={self.name}, valid={self.validate()})"

    def __repr__(self) -> str:
        return str(self)

    def __eq__(self, other: any) -> bool:
        if not isinstance(other, Authority): return False

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

    def serialize(self) -> any:
        return {"r": self.requester.serialize(), "a": self.authority.serialize(), "s": self.signature.serialize()}

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

    def serialize(self) -> any:
        return {"a": self.approver.serialize(), "r": self.request.serialize(), "s": self.signature.serialize()}

    def validate(self) -> bool:
        return self.approver.validate() and self.request.validate() and self._validate_signature(key=self.approver.key)

    def __str__(self) -> str:
        return f"AuthorityApproval(authority={self.request.authority}, approver={self.approver}, valid={self.validate()})"

    def __repr__(self) -> str:
        return str(self)
