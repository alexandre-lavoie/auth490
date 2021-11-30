from abc import ABC, abstractclassmethod, abstractmethod
import json
import zlib
import base64
import qrcode
import io
import re
from PIL import Image
from typing import Tuple

def qr_code_decompress(data: str) -> Tuple[str, str]:
    header, body = data.split(":")
    body = bytes([int(d) + 45 for d in re.findall(r"\d\d", body)]).decode()

    return header, body

def qr_code_compress(header: str, body: str) -> str:
    data = ''.join("%02d" % (ord(c) - 45) for c in body)

    return header + ":" + data

def compress(data: dict) -> str:
    dumped_data = json.dumps(data, separators=(',', ':'))
    compressed_data = zlib.compress(dumped_data.encode())
    b64_data = base64.urlsafe_b64encode(compressed_data).decode()

    return b64_data

def decompress(data: str) -> dict:
    if isinstance(data, str):
        data = data.encode()

    compressed_data = base64.urlsafe_b64decode(data)
    raw_data = zlib.decompress(compressed_data).decode()
    out_data = json.loads(raw_data)

    return out_data

class Serializable(ABC):
    @abstractclassmethod
    def get_type(cls) -> str:
        pass

    def b64_serialize(self, with_signature: bool=True) -> str:
        raw_data = self.raw_serialize()

        if isinstance(raw_data, dict):
            if not with_signature and 's' in raw_data:
                del raw_data["s"]

            b64_data = compress(raw_data)
        else:
            b64_data = raw_data

        return b64_data

    def serialize(self) -> str:
        return qr_code_compress(self.get_type().upper(), self.b64_serialize())

    @abstractmethod
    def raw_serialize(self) -> dict:
        return {
            "t": self.get_type().lower()
        }

    @classmethod
    def b64_deserialize(cls, data: str) -> "Self":
        try:
            out_data = decompress(data)
        except Exception as err:
            out_data = data

        return cls.raw_deserialize(out_data)

    @classmethod
    def deserialize(cls, data: str) -> "Self":
        header, body = qr_code_decompress(data)

        if not header.lower() == cls.get_type():
            raise Exception("Wrong deserialization type.")

        return cls.b64_deserialize(body)

    @abstractclassmethod
    def raw_deserialize(cls, data: dict) -> "Self":
        pass

    def qr_code(self) -> qrcode.QRCode:
        qr = qrcode.QRCode(
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=1,
            border=1
        )
        qr.add_data(self.serialize())
        qr.make(fit=True)

        return qr

    def qr_code_image_bytes(self) -> io.BytesIO:
        data = io.BytesIO()
        img = self.qr_code().make_image()
        img.save(data, "PNG")

        return data

    def qr_code_uri(self) -> str:
        header = "data:img/png;base64,"
        b64_img = base64.b64encode(self.qr_code_image_bytes().getvalue()).decode()
        uri = header + b64_img

        return uri

    def str_data(self) -> dict:
        return {}

    def __str__(self) -> str:
        values = ', '.join(f"{k}={v}" for k, v in self.str_data().items())

        return self.__class__.__name__ + f"({values})"

    def __repr__(self) -> str:
        return str(self)

def is_abstract(cls):
    return bool(getattr(cls, "__abstractmethods__", False))

def cls_deserialize(cls, data: dict) -> Serializable:
    if is_abstract(cls):
        for scls in cls.__subclasses__():
            out = cls_deserialize(scls, data)
            if out: 
                return out
        return None

    if cls.get_type() == data["t"]:
        return cls.raw_deserialize(data)

    return None

def deserialize(data: str) -> Serializable:
    header, body = qr_code_decompress(data)

    if header == "PK":
        from .crypto import PrivateKey
        return PrivateKey.raw_deserialize(body)
    elif header == "K":
        from .crypto import PublicKey
        return PublicKey.raw_deserialize(body)
    else:
        result = cls_deserialize(Serializable, decompress(body))
        if result:
            return result

    raise Exception("Unimplemented deserialize.")
