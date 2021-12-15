from auth490 import *

def test():
    print("Registry\n")

    auth490 = Authority(
        name="Auth490",
        key=RSAPrivateKey.generate()
    )
    print("Main Authority:", auth490)

    registry = Registry(
        main_authority=auth490
    )

    government = Authority(
        name="Government of Location",
        key=RSAPrivateKey.generate()
    )
    print("Government:", government)

    government_request = AuthorityRequest(
        requester=auth490,
        authority=government
    )
    print("Government Request:", government_request)
    registry.insert(government_request)

    government_approval = AuthorityApproval(
        approver=auth490,
        request=government_request
    )
    government_approval.sign(auth490)
    print("Government Approval:", government_approval)
    registry.insert(government_approval)

    government_permission_request = PermissionRequest(
        requester=government,
        permissions=[PermissionType.DATA_CREATION]
    )
    print("Government Permission Request:", government_permission_request)
    registry.insert(government_permission_request)

    government_approval = PermissionApproval(
        approver=auth490,
        permissions=government_permission_request.permissions,
        request=government_permission_request
    )
    print("Government Permission Approval:", government_approval)
    registry.insert(government_approval)

    print("Registry:", registry)

    print("\nData\n")

    individual = Individual(
        key=RSAPrivateKey.generate()
    )
    print("Individual:", individual)

    individual_name = Data(
        provider=government,
        recipient=individual,
        type=DataType.NAME,
        value="JOHN DOE"
    )

    individual_vaccine = Data(
        provider=government,
        recipient=individual,
        type=DataType.VACCINE,
        value="PFIZER"
    )
    print(deserialize(individual_vaccine.serialize()))
    print("Individual Data:", [individual_name, individual_vaccine])

    transfer = DataTransfer(
        provider=individual, 
        datas=[individual_name, individual_vaccine], 
        challenge="TEST"
    )
    transfer.sign(individual)
    print("Transfer:", transfer)
    print("Data Length:", len(transfer.serialize()), "/", "7089")


if __name__ == "__main__":
    test()
