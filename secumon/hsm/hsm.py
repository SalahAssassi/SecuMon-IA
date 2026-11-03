"""Interface HSM (M3) via PKCS#11 : les cles MAC des terminaux ne quittent jamais SoftHSM2."""
import os

import pkcs11
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import NoSuchKey

DEFAULT_MODULE = "/usr/lib/softhsm/libsofthsm2.so"


def key_label(terminal_id: str) -> str:
    return f"TAK-{terminal_id}"


class HsmKeyNotFound(KeyError):
    """Aucune cle dans le HSM pour ce terminal."""


class HsmMacKey:
    """Cle AES stockee dans le HSM : on peut l'UTILISER, jamais la LIRE."""

    def __init__(self, key):
        self._key = key

    def cmac(self, data: bytes) -> bytes:
        return self._key.sign(data, mechanism=Mechanism.AES_CMAC)


class Hsm:
    def __init__(self, label: str, pin: str, module: str = DEFAULT_MODULE, rw: bool = False):
        token = pkcs11.lib(module).get_token(token_label=label)
        self.session = token.open(user_pin=pin, rw=rw)

    @classmethod
    def from_env(cls, rw: bool = False) -> "Hsm":
        return cls(os.environ["SECUMON_HSM_LABEL"], os.environ["SECUMON_HSM_PIN"],
                   os.environ.get("SECUMON_PKCS11_MODULE", DEFAULT_MODULE), rw=rw)

    def close(self) -> None:
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def terminal_key(self, terminal_id: str) -> HsmMacKey:
        try:
            key = self.session.get_key(object_class=ObjectClass.SECRET_KEY, key_type=KeyType.AES,
                                       label=key_label(terminal_id))
        except NoSuchKey:
            raise HsmKeyNotFound(terminal_id) from None
        return HsmMacKey(key)

    def import_terminal_key(self, terminal_id: str, value: bytes) -> HsmMacKey:
        key = self.session.create_object({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.AES,
            Attribute.LABEL: key_label(terminal_id),
            Attribute.VALUE: value,
            Attribute.TOKEN: True,          # cle persistante dans le token
            Attribute.PRIVATE: True,        # accessible uniquement apres login
            Attribute.SIGN: True,
            Attribute.VERIFY: True,
            Attribute.ENCRYPT: False,       # une cle = un usage : MAC uniquement
            Attribute.DECRYPT: False,
            Attribute.WRAP: False,
            Attribute.UNWRAP: False,
            Attribute.DERIVE: False,
            Attribute.SENSITIVE: True,      # jamais lisible en clair
            Attribute.EXTRACTABLE: False,   # jamais exportable
        })
        return HsmMacKey(key)

    def delete_terminal_key(self, terminal_id: str) -> None:
        for obj in self.session.get_objects({Attribute.CLASS: ObjectClass.SECRET_KEY,
                                             Attribute.LABEL: key_label(terminal_id)}):
            obj.destroy()
