from abc import ABC, abstractclassmethod, abstractmethod
import json
import zlib
import base64
import qrcode
import io
import re

def deserialize(data: any) -> any:
    b64 = bytes([int(d) + 45 for d in re.findall(r"\d\d", data.split(":")[1])])
    compressed = base64.urlsafe_b64decode(b64)

    try:
        raw = zlib.decompress(compressed)
        j = json.loads(raw)

        if j["t"] == "aa":
            from .authority import AuthorityApproval
            return AuthorityApproval.deserialize(j)
        elif j["t"] == "pa":
            from .permissions import PermissionApproval
            return PermissionApproval.deserialize(j)
        elif j["t"] == "ar":
            from .authority import AuthorityRequest
            return AuthorityRequest.deserialize(j)
        elif j["t"] == "pr":
            from .permissions import PermissionRequest
            return PermissionRequest.deserialize(j)
        elif j["t"] == "dr":
            from .data import DataRequest
            return DataRequest.deserialize(j)
        elif j["t"] == "dt":
            from .data import DataTransfer
            return DataTransfer.deserialize(j)
        elif j["t"] == "d":
            from .data import Data
            return Data.deserialize(j)
        else: 
            raise Exception("Unimplemented deserialize " + j["t"] + ".")
    except Exception as err:
        if len(compressed) == 256:
            from .crypto import PrivateKey
            return PrivateKey.deserialize(b64)
        elif len(compressed) == 128:
            from .crypto import PublicKey
            return PublicKey.deserialize(b64)
        else:
            raise err

class Serializable(ABC):
    @abstractmethod
    def serialize(self) -> any:
        return None

    @abstractclassmethod
    def deserialize(self, data: any) -> any:
        return None

    def b64_serialize(self, with_signature: bool=True) -> str:
        serialized_data = self.serialize()

        if isinstance(serialized_data, dict):
            if not with_signature:
                del serialized_data['s']

            dumped_data = json.dumps(serialized_data, separators=(',', ':'))
            compressed_data = zlib.compress(dumped_data.encode())
            data = base64.urlsafe_b64encode(compressed_data).decode()
        else:
            data = serialized_data

        return data

    @classmethod
    def b64_deserialize(cls, data: any) -> any:
        compressed_data = base64.urlsafe_b64decode(data)
        
        try:
            raw_data = zlib.decompress(compressed_data).decode()
            out_data = json.loads(raw_data)
        except Exception as err:
            out_data = data

        return cls.deserialize(out_data)    

    def qr_serialize(self) -> str:
        data = self.b64_serialize(with_signature=True)
        mapped_data = self.get_str_type().upper() + ":" + ''.join("%02d" % (ord(c) - 45) for c in data)

        return mapped_data

    @classmethod
    def qr_deserialize(cls, data: any) -> any:
        raw = bytes([int(d) + 45 for d in re.findall(r"\d\d", data.split(":")[1])])

        return cls.b64_deserialize(raw)

    def qr_uri(self) -> str:
        qr = qrcode.QRCode(
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=1,
            border=1
        )
        qr.add_data(self.qr_serialize())
        qr.make(fit=True)

        data = io.BytesIO()
        img = qr.make_image()
        img.save(data, "PNG")

        uri = 'data:img/png;base64,' + base64.b64encode(data.getvalue()).decode()

        return uri
