import sys
from pathlib import Path

# pytest puts backend/tests on the path, the tests import the backend package itself
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
