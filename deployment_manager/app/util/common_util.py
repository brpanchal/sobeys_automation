import os
from pathlib import Path


def get_root_path():
    project_root = Path(os.environ.get("PROJECT_ROOT", ".")).resolve()
    return project_root