from .authority import Authority, AuthorityRequest, AuthorityApproval
from .permissions import PermissionType, PermissionRequest, PermissionApproval
from .crypto import KeyHolder

from typing import List

class Registry:
    __main_authority: Authority
    
    __authority_requests: List[AuthorityRequest]
    __authority_approvals: List[AuthorityApproval]

    __permission_requests: List[PermissionRequest]
    __permission_approvals: List[PermissionApproval]

    def __init__(self, main_authority: Authority):
        self.__main_authority = main_authority

        if not main_authority.validate():
            raise Exception("Invalid main authority.")

        self.__authority_requests = []
        self.__authority_approvals = []

        self.__permission_requests = []
        self.__permission_approvals = []

    @property
    def authorities(self):
        return [self.__main_authority] + [approval.request.authority for approval in self.__authority_approvals]

    def has_permissions(self, entity: KeyHolder, permission_types: List[PermissionType]):
        if entity == self.__main_authority: 
            return True

        if not isinstance(permission_types, list):
            permission_types = [permission_types]

        for permission_type in permission_types:
            for approval in self.__permission_approvals:
                if not approval.request.requester == entity: continue
                if not permission_type in approval.permissions: continue

                break
            else:
                return False

        return True

    def request_authority(self, request: AuthorityRequest):
        if not request.validate():
            raise Exception("Failed request authority validation.")

        self.__authority_requests.append(request)

    def approve_authority(self, approval: AuthorityApproval):
        if not approval.validate():
            raise Exception("Failed approve authority validation.")

        if not self.has_permissions(approval.approver, PermissionType.AUTHORITY_APPROVAL):
            raise Exception("Entity cannot approve authority.")

        self.__authority_requests.remove(approval.request)
        self.__authority_approvals.append(approval)

    def request_permission(self, request: PermissionRequest):
        if not request.validate():
            raise Exception("Failed request permission validation.")

        self.__permission_requests.append(request)

    def approve_permissions(self, approval: PermissionApproval):
        if not approval.validate():
            raise Exception("Failed approve permission valdation.")

        if not self.has_permissions(approval.approver, PermissionType.PERMISSION_APPROVAL):
            raise Exception("Entity cannot approve permission.")

        if not all(permission in approval.request.permissions for permission in approval.permissions):
            raise Exception("Trying to add unrequested permissions.")

        self.__permission_requests.remove(approval.request)
        self.__permission_approvals.append(approval)

    def __str__(self) -> str:
        return f"Registry(authorities={self.__authority_approvals}, permissions={self.__permission_approvals})"

    def __repr__(self) -> str:
        return str(self)
