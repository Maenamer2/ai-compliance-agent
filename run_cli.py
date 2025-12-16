"""Standalone CLI script that works without package installation."""

import sys
import os
from pathlib import Path

# Add project root to path - ensure absolute path
project_root = Path(__file__).parent.resolve()
sys.path.insert(0, str(project_root))

# Also add to PYTHONPATH for Windows
os.environ['PYTHONPATH'] = str(project_root) + os.pathsep + os.environ.get('PYTHONPATH', '')

# Verify src is importable
if not (project_root / 'src' / '__init__.py').exists():
    print(f"Error: Cannot find src package at {project_root / 'src'}")
    sys.exit(1)

# Now import and run the CLI
try:
    from src.cli import cli
except ModuleNotFoundError as e:
    print(f"Import error: {e}")
    print(f"Python path: {sys.path[:3]}")
    print(f"Project root: {project_root}")
    print(f"CWD: {Path.cwd()}")
    raise

if __name__ == "__main__":
    cli()
