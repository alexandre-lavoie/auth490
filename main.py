from auth490.authority import *
from auth490.crypto import *
from auth490.registry import *
from auth490.people import *
from auth490.verification import *
from auth490.data import *

def test():
    print("Registry\n")

    auth490_private_key = PrivateKey.generate()
    auth490 = Authority(
        name="Auth490",
        key=auth490_private_key
    )
    auth490.sign(auth490_private_key)
    print("Main Authority:", auth490)

    registry = Registry(
        main_authority=auth490
    )

    government_private_key = PrivateKey.generate()
    government = Authority(
        name="Government of Location",
        key=government_private_key
    )
    government.sign(government_private_key)
    print("Government:", government)

    government_request = AuthorityRequest(
        requester=auth490,
        authority=government
    )
    government_request.sign(auth490_private_key)
    print("Government Request:", government_request)
    registry.request_authority(request=government_request)
    
    government_approval = AuthorityApproval(
        approver=auth490,
        request=government_request
    )
    government_approval.sign(auth490_private_key)
    print("Government Approval:", government_approval)
    registry.approve_authority(approval=government_approval)

    government_permission_request = PermissionRequest(
        requester=government,
        permissions=[PermissionType.DATA_CREATION]
    )
    government_permission_request.sign(government_private_key)
    print("Government Permission Request:", government_permission_request)
    registry.request_permission(request=government_permission_request)

    government_approval = PermissionApproval(
        approver=auth490,
        permissions=government_permission_request.permissions,
        request=government_permission_request
    )
    government_approval.sign(auth490_private_key)
    print("Government Permission Approval:", government_approval)
    registry.approve_permissions(approval=government_approval)

    print("Registry:", registry)

    print("\nData\n")

    person_private_key = PrivateKey.generate()
    person = Person(
        key=person_private_key
    )
    person.sign(person_private_key)
    print("Person:", person)

    person_name = Data(
        provider=government,
        recipient=person,
        type=DataType.NAME,
        value="JOHN DOE"
    )
    person_name.sign(government_private_key)

    person_vaccine = Data(
        provider=government,
        recipient=person,
        type=DataType.VACCINE,
        value="PFIZER"
    )
    person_vaccine.sign(government_private_key)
    print("Person Data:", [person_name, person_vaccine])

    verifier = Verifier(
        registry=registry,
        verifier=government,
        private_key=government_private_key,
        challenge="CHALLENGE"
    )

    data_request = verifier.request_data(types=[DataType.NAME])
    print("Government Request:", data_request)

    if not data_request.validate():
        raise Exception("Invalid data request.")

    data_response = DataTransfer(
        provider=person,
        datas=[person_name, person_vaccine],
        challenge=data_request.challenge
    )
    data_response.sign(person_private_key)
    print("Person Response:", data_response)
    print("QR Code Size:", len(data_response.qr_serialize()), "/", "7089")

    verifier.validate_data(data_response)

if __name__ == "__main__":
    test()
