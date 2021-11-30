from typing import Union

from .crypto import KeyHolder, Signable, PublicKey, PrivateKey, Signature

class Individual(KeyHolder):
    def __init__(self, key: Union[PrivateKey, PublicKey]):
        KeyHolder.__init__(self, key=key)

    @classmethod
    def get_type(cls) -> str:
        return "u"

    @classmethod
    def raw_deserialize(self, data: dict) -> "Individual":
        individual = Individual(
            key=PublicKey.raw_deserialize(data["k"])
        )
        individual.try_add_sign(data)

        return individual
