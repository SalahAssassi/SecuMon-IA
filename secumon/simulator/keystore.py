"""Coffre de cles du terminal simule (M1) : simule la memoire securisee d'un TPE."""
import os
from pathlib import Path

KEYSTORE_DIR = Path(os.environ.get("SECUMON_TERMINAL_KEYSTORE",
                                   Path.home() / ".secumon" / "terminal-keys"))


def _path(terminal_id: str) -> Path:
    return KEYSTORE_DIR / f"{terminal_id}.key"


def save_terminal_key(terminal_id: str, value: bytes) -> None:
    KEYSTORE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(KEYSTORE_DIR, 0o700)
    # Fichier cree directement avec les droits 600 : jamais lisible par un autre utilisateur
    fd = os.open(_path(terminal_id), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(value.hex())


def load_terminal_key(terminal_id: str) -> bytes:
    path = _path(terminal_id)
    if not path.exists():
        raise RuntimeError(f"Aucune cle pour {terminal_id} : "
                           f"lancez 'python -m secumon.hsm.provision {terminal_id}'")
    return bytes.fromhex(path.read_text().strip())
