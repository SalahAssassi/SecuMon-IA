"""Ceremonie de cles (M3) : une TAK aleatoire par terminal, injectee dans le HSM (non extractible)
et dans le terminal simule. Le KCV permet de verifier que les deux ont recu la meme cle."""
import argparse
import secrets

from secumon.common.config import load_dotenv
from secumon.hsm.hsm import Hsm, HsmKeyNotFound
from secumon.iso8583.mac import kcv
from secumon.simulator.keystore import load_terminal_key, save_terminal_key


def main() -> None:
    p = argparse.ArgumentParser(description="Ceremonie de cles SecuMon-IA")
    p.add_argument("terminals", nargs="+", help="identifiants des terminaux (ex. TPE-0001)")
    p.add_argument("--rotate", action="store_true", help="remplace une cle existante")
    args = p.parse_args()
    load_dotenv()

    with Hsm.from_env(rw=True) as hsm:
        for terminal_id in args.terminals:
            try:
                hsm.terminal_key(terminal_id)
                if not args.rotate:
                    print(f"{terminal_id} : cle deja presente (utilisez --rotate pour la remplacer)")
                    continue
                hsm.delete_terminal_key(terminal_id)
            except HsmKeyNotFound:
                pass

            value = secrets.token_bytes(16)                       # AES-128 aleatoire
            hsm_key = hsm.import_terminal_key(terminal_id, value)  # cote HSM
            save_terminal_key(terminal_id, value)                  # cote terminal
            hsm_kcv, terminal_kcv = kcv(hsm_key), kcv(load_terminal_key(terminal_id))
            status = "OK" if hsm_kcv == terminal_kcv else "ERREUR"
            print(f"{terminal_id} : TAK injectee - KCV HSM={hsm_kcv} KCV terminal={terminal_kcv} [{status}]")


if __name__ == "__main__":
    main()
