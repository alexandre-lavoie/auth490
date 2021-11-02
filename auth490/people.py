from .crypto import KeyHolder, Signable, PublicKey

class Person(Signable, KeyHolder):
    def __init__(self, key: PublicKey):
        KeyHolder.__init__(self, key=key)

    def serialize(self) -> any:
        return {"k": self.key.serialize(), "s": self.signature.serialize()}

    def validate(self) -> bool:
        return self._validate_signature(key=self.key)

    def __eq__(self, other: any) -> bool:
        if not isinstance(other, Person): return False

        return self.key == other.key

    def __str__(self) -> str:
        return f"Person(valid={self.validate()})"

    def __repr__(self) -> str:
        return str(self)
