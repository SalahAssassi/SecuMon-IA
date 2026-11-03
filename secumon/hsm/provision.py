"""Ceremonie de cles (M3) : pour chaque terminal, une TAK (MAC) et une TPK (PIN) aleatoires,
injectees dans le HSM et dans le terminal ; une ZPK unique generee DANS le HSM.
Les KCV permettent de verifier que HSM et terminal ont recu les memes cles."""
import argparse
import secrets

from secumon.common.config import load_dotenv
from secumon.hsm.hsm import ZPK_LABEL, Hsm, HsmKeyNotFound
from secumon.hsm.pinblock import SoftwareAes, pin_key_kcv
from secumon.iso8583.mac import kcv
from secumon.simulator.keystore import load_terminal_key, save_terminal_key


def ensure_zone_pin_key(hsm: Hsm) -> None:
    try:
        zpk = hsm.zone_pin_key()
        print(f"{ZPK_LABEL} : deja presente - KCV={pin_key_kcv(zpk)}")
    except HsmKeyNotFound:
        zpk = hsm.generate_zone_pin_key()
        print(f"{ZPK_LABEL} : generee dans le HSM - KCV={pin_key_kcv(zpk)}")


def provision_terminal(hsm: Hsm, terminal_id: str, rotate: bool) -> None:
    try:
        hsm.terminal_key(terminal_id)
        hsm.terminal_pin_key(terminal_id)
        if not rotate:
            print(f"{terminal_id} : cles deja presentes (utilisez --rotate pour les remplacer)")
            return
    except HsmKeyNotFound:
        pass
    hsm.delete_terminal_key(terminal_id)
    hsm.delete_key(f"TPK-{terminal_id}")

    tak = secrets.token_bytes(16)
    hsm_tak = hsm.import_terminal_key(terminal_id, tak)
    save_terminal_key(terminal_id, tak, "key")

    tpk = secrets.token_bytes(16)
    hsm_tpk = hsm.import_terminal_pin_key(terminal_id, tpk)
    save_terminal_key(terminal_id, tpk, "tpk")

    tak_ok = kcv(hsm_tak) == kcv(load_terminal_key(terminal_id, "key"))
    tpk_ok = pin_key_kcv(hsm_tpk) == pin_key_kcv(SoftwareAes(load_terminal_key(terminal_id, "tpk")))
    print(f"{terminal_id} : TAK KCV={kcv(hsm_tak)} [{'OK' if tak_ok else 'ERREUR'}] - "
          f"TPK KCV={pin_key_kcv(hsm_tpk)} [{'OK' if tpk_ok else 'ERREUR'}]")


def main() -> None:
    p = argparse.ArgumentParser(description="Ceremonie de cles SecuMon-IA")
    p.add_argument("terminals", nargs="+", help="identifiants des terminaux (ex. TPE-0001)")
    p.add_argument("--rotate", action="store_true", help="remplace les cles existantes")
    args = p.parse_args()
    load_dotenv()
    with Hsm.from_env(rw=True) as hsm:
        ensure_zone_pin_key(hsm)
        for terminal_id in args.terminals:
            provision_terminal(hsm, terminal_id, args.rotate)


if __name__ == "__main__":
    main()
