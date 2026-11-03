"""Auto-test du HSM (M3) : connexion au token, cle non extractible, compatibilite AES-CMAC."""
import os
import secrets

import pkcs11
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.cmac import CMAC
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

from secumon.common.config import load_dotenv

MODULE = os.environ.get("SECUMON_PKCS11_MODULE", "/usr/lib/softhsm/libsofthsm2.so")


def main() -> None:
    load_dotenv()
    lib = pkcs11.lib(MODULE)
    token = lib.get_token(token_label=os.environ["SECUMON_HSM_LABEL"])
    print(f"Token trouve : {token.label}")

    key_value = secrets.token_bytes(16)          # cle AES-128 de TEST
    message = b"0100 SecuMon-IA test AES-CMAC"

    with token.open(user_pin=os.environ["SECUMON_HSM_PIN"]) as session:
        key = session.create_object({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.AES,
            Attribute.VALUE: key_value,
            Attribute.TOKEN: False,         # cle de session : effacee a la fermeture
            Attribute.SIGN: True,
            Attribute.VERIFY: True,
            Attribute.SENSITIVE: True,      # valeur jamais lisible en clair
            Attribute.EXTRACTABLE: False,   # impossible a exporter
        })
        hsm_mac = key.sign(message, mechanism=Mechanism.AES_CMAC)

        try:
            key[Attribute.VALUE]
            print("ATTENTION : la valeur de la cle est lisible !")
        except pkcs11.PKCS11Error as exc:
            print(f"Lecture de la cle refusee par le HSM (attendu) : {type(exc).__name__}")

    cmac = CMAC(algorithms.AES(key_value))
    cmac.update(message)
    local_mac = cmac.finalize()

    print(f"MAC calcule par le HSM       : {hsm_mac.hex().upper()}")
    print(f"MAC calcule par cryptography : {local_mac.hex().upper()}")
    print("RESULTAT : COMPATIBLE" if hsm_mac == local_mac else "RESULTAT : INCOMPATIBLE")


if __name__ == "__main__":
    main()
