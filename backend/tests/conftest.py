"""Pytest configuration for the backend test suite.

Loads the lab FastAPI app into ``sys.modules`` under synthetic names
(``_lab_auth``, ``_lab_main``) so detector accuracy tests can import and use
the lab app in-process without any sys.path manipulation that would break the
backend's own ``app.*`` imports.

How it works
------------
The lab uses bare ``from app.xxx import`` internally (relative to ``lab/``).
We temporarily insert ``lab/`` at position 0, import the lab modules (which
registers ``app`` as ``lab/app`` in ``sys.modules`` under a temporary alias),
then replace the temporary ``sys.modules['app']`` entry with a sentinel so
subsequent imports of ``backend/app`` work normally.
"""

from __future__ import annotations

import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).parents[2]
_LAB_DIR = _PROJECT_ROOT / "lab"

# Save any existing 'app' entry (there won't be one at conftest time, but
# be defensive).
_prior_app = sys.modules.get("app")

# Insert lab/ first so "app" resolves to lab/app.
sys.path.insert(0, str(_LAB_DIR))

import os  # noqa: E402

os.environ.setdefault("LAB_SECURE_JWT_SECRET", "test-only-synthetic-secure-secret-32b")

import app.auth as _lab_auth  # noqa: E402
import app.data as _lab_data  # noqa: E402
import app.main as _lab_main  # noqa: E402

# Remove lab/ from sys.path front position.
sys.path.pop(0)

# Unregister "app" and "app.*" from sys.modules so backend/app can claim the
# "app" name when backend tests import it normally.
for key in list(sys.modules):
    if key == "app" or key.startswith("app."):
        sys.modules.pop(key, None)

# Restore any prior entry (defensive).
if _prior_app is not None:
    sys.modules["app"] = _prior_app

# Re-register the lab modules under private names so the accuracy test can
# reach them without triggering re-import or namespace collision.
sys.modules["_lab_auth"] = _lab_auth
sys.modules["_lab_main"] = _lab_main
sys.modules["_lab_data"] = _lab_data
