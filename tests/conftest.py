import sys
from pathlib import Path

# Make the `sentinel` package importable from tests.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
