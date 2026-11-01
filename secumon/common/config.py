"""Chargement minimal du fichier .env (sans dependance externe)."""
import os
from pathlib import Path


def load_dotenv(path: str = ".env") -> None:
    """Charge les variables KEY=VALUE du .env sans ecraser l'environnement existant."""
    env_file = Path(path)
    if not env_file.exists():
        return
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())