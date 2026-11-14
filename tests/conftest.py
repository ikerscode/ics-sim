import os

os.environ.setdefault("SECLAB_ALLOWED_HOSTS", "testserver")  # FastAPI TestClient host

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
