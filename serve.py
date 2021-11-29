from flask import Flask, request, render_template, Response
from auth490 import Authority, Registry, PrivateKey, PublicKey, Person
from auth490.crypto import KeyHolder
from auth490.serialize import deserialize
from auth490.authority import AuthorityRequest, AuthorityApproval
from auth490.permissions import PermissionRequest, PermissionType, PermissionApproval
from auth490.data import DataType, DataRequest, Data, DataTransfer
from auth490.wallet import Wallet
import qrcode
import base64
import os.path
import random
from typing import Union

app = Flask(__name__)

if os.path.exists(".pk"):
    with open(".pk") as h:
        main_authority_key = PrivateKey.qr_deserialize(h.read())
else:
    main_authority_key = PrivateKey.generate()

main_authority = Authority(
    name="Auth490", 
    key=main_authority_key.public_key
)
main_authority.sign(main_authority_key)
registry = Registry(
    main_authority=main_authority,
    main_authority_key=main_authority_key
)

def get_key_holder(key: Union[PrivateKey, PublicKey]) -> KeyHolder:
    if isinstance(key, PrivateKey):
        public_key = key.public_key
    else:
        public_key = key

    for authority in registry.authorities:
        if authority.key == public_key:
            return authority

    if not isinstance(key, PrivateKey):
        raise Exception("Cannot get key holder with this key.")

    person = Person(key.public_key)
    person.sign(key)

    return person

@app.route("/")
def main_home():
    return render_template("index.html")

@app.route("/client")
def client_home():
    return render_template("client/index.html")

@app.route("/server")
def server_home():
    return render_template("server/index.html")

@app.route("/client/key")
def client_key():
    private_key = PrivateKey.generate()

    return render_template("client/key.html", private_key=private_key)

@app.route("/client/view", methods=["GET", "POST"])
def client_view():
    data = None
    if request.method == "POST":
        data = str(deserialize(request.form['data']))

    return render_template("client/view.html", data=data)

@app.route("/server/registry", methods=["GET"])
def server_registry():
    return render_template("server/registry.html", registry=registry)

@app.route("/server/registry", methods=["POST"])
def server_registry_post():
    data = deserialize(request.form["data"])

    if isinstance(data, AuthorityRequest):
        registry.request_authority(data)
    elif isinstance(data, PermissionRequest):
        registry.request_permission(data)
    elif isinstance(data, AuthorityApproval):
        registry.approve_authority(data)
    elif isinstance(data, PermissionApproval):
        registry.approve_permissions(data)
    else:
        raise Exception("Unimplemented registry for " + str(data))

    return render_template("server/registry.html", registry=registry)

@app.before_request 
def before_request_callback(): 
    request.wallet = Wallet.load(request)

@app.after_request
def after_request_callback(response: Response):
    return request.wallet.dump(response)

@app.route("/client/registry")
def client_registry():
    return render_template("client/registry.html", PermissionType=PermissionType, wallet=request.wallet)

@app.route("/client/registry/authority", methods=["POST"])
def client_registry_authority():
    name = request.form["name"]

    requester_key = deserialize(request.form["requester"])
    requester = get_key_holder(requester_key)

    authority_key = deserialize(request.form["key"])
    authority = Authority(
        name,
        authority_key.public_key
    )
    authority.sign(authority_key)

    authority_request = AuthorityRequest(
        requester,
        authority
    )
    authority_request.sign(requester_key)

    return render_template("client/qr_response.html", data=authority_request)

@app.route("/client/registry/permission", methods=["POST"])
def client_registry_permission():
    permissions = [PermissionType(int(value)) for value in request.form.getlist("permissions")]

    requester_key = deserialize(request.form["requester"])
    requester = get_key_holder(requester_key)

    permission_request = PermissionRequest(
        requester,
        permissions
    )
    permission_request.sign(requester_key)

    return render_template("client/qr_response.html", data=permission_request)

@app.route("/client/registry/approve", methods=["POST"])
def client_registry_approve():
    approver_key = deserialize(request.form["approver"])
    approver = get_key_holder(approver_key)

    data = deserialize(request.form["data"])

    if isinstance(data, AuthorityRequest):
        approval = AuthorityApproval(
            approver,
            data
        )
    elif isinstance(data, PermissionRequest):
        approval = PermissionApproval(
            approver,
            data.permissions,
            data
        )
    else:
        raise Exception("Unimplemented approval for " + str(data))

    approval.sign(approver_key)

    return render_template("client/qr_response.html", data=approval)

@app.route("/client/data")
def client_data():
    return render_template("client/data.html", DataType=DataType, default_challenge=random.randrange(0, 10000), wallet=request.wallet)

@app.route("/client/wallet")
def client_wallet():
    return render_template("client/wallet.html", wallet=request.wallet)

@app.route("/client/wallet", methods=["POST"])
def client_wallet_post():
    data = deserialize(request.form["data"])

    request.wallet.add(data)

    return render_template("client/wallet.html", wallet=request.wallet)

@app.route("/client/wallet/delete/<index>", methods=["POST"])
def client_wallet_delete(index):
    request.wallet.remove(int(index))

    return render_template("client/wallet.html", wallet=request.wallet)

@app.route("/client/data/request", methods=["POST"])
def client_data_request():
    requester_key = deserialize(request.form["requester"])
    requester = get_key_holder(requester_key)

    data_types = [DataType(int(dt)) for dt in request.form.getlist("data_types")]

    challenge = request.form["challenge"]

    data_request = DataRequest(
        requester,
        data_types,
        challenge
    )
    data_request.sign(requester_key)

    return render_template("client/qr_response.html", data=data_request)

@app.route("/client/data/create", methods=["POST"])
def client_data_create():
    data_type = DataType(int(request.form["data_type"]))
    value = request.form["value"]

    provider_key = deserialize(request.form["provider"])
    provider = get_key_holder(provider_key)

    data_request = deserialize(request.form["request"])
    recipient = data_request.requester

    data = Data(
        provider,
        recipient,
        value,
        data_type
    )
    data.sign(provider_key)

    return render_template("client/qr_response.html", data=data)

@app.route("/client/data/transfer", methods=["POST"])
def client_data_transfer():
    data = [deserialize(d) for d in request.form["data"].split(",")]

    provider_key = deserialize(request.form["provider"])
    provider = get_key_holder(provider_key)

    data_request = deserialize(request.form["request"])

    data_transfer = DataTransfer(
        provider,
        data,
        data_request.challenge
    )
    data_transfer.sign(provider_key)

    return render_template("client/qr_response.html", data=data_transfer)

@app.route("/client/data/verify", methods=["POST"])
def client_data_verify():
    data_transfer = deserialize(request.form["transfer"])
    data_request = deserialize(request.form["request"])
    trusted = True

    if not data_transfer.challenge == data_request.challenge:
        raise Exception("Challenges do not match.")

    if not data_transfer.validate():
        raise Exception("Invalid transfer.")

    is_create = registry.is_authority(data_transfer.provider)

    for data in data_transfer.datas:
        if not registry.has_permissions(data.provider, PermissionType.DATA_CREATION):
            trusted = False
        if not is_create and not data.recipient == data_transfer.provider:
            raise Exception("Data recipient does not match data provider.")

    return render_template("client/data_response.html", transfer=data_transfer, trusted=trusted)

@app.route("/admin")
def admin():
    return render_template("admin.html", private_key=main_authority_key)

app.run(host="0.0.0.0", port=5000, debug=True)
