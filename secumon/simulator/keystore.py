"""Coffre de cles du terminal simule (M1) : simule la memoire securisee d'un TPE.
TPE-0001.key = cle MAC (TAK) ; TPE-0001.tpk = cle PIN (TPK)."""
import os
from pathlib import Path

KEYSTORE_DIR = Path(os.environ.get("SECUMON_TERMINAL_KEYSTORE",
                                   Path.home() / ".secumon" / "terminal-keys"))


def _path(terminal_id: str, kind: str) -> Path:
    return KEYSTORE_DIR / f"{terminal_id}.{kind}"


def save_terminal_key(terminal_id: str, value: bytes, kind: str = "key") -> None:
    KEYSTORE_DIR.mkdir(parents=True, exist_ok=True)
    # 0o700 = proprietaire seul : le plus restrictif possible pour un dossier (faux positif Semgrep)
    os.chmod(KEYSTORE_DIR, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    fd = os.open(_path(terminal_id, kind), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(value.hex())


def load_terminal_key(terminal_id: str, kind: str = "key") -> bytes:
    path = _path(terminal_id, kind)
    if not path.exists():
        raise RuntimeError(f"Aucune cle '{kind}' pour {terminal_id} : "
                           f"lancez 'python -m secumon.hsm.provision {terminal_id}'")
    return bytes.fromhex(path.read_text().strip())
