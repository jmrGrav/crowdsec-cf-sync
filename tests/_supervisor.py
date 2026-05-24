"""Test helper: load the supervisor script as an importable module.

The supervisor file (`crowdsec-cf-sync`) has no `.py` extension and calls
`_setup_logging()` at import time, which opens `/var/log/crowdsec/cf-sync.log`
via `RotatingFileHandler`. That handler requires root privileges.

This helper:
  1. Monkey-patches `logging.handlers.RotatingFileHandler` to a no-op
     so import succeeds as a regular user.
  2. Uses `importlib.machinery.SourceFileLoader` since the file has no `.py`.

Each `load_supervisor()` call returns a freshly-imported module instance,
allowing tests to mutate module-level state (path constants) without
leaking across test cases.

Stdlib-only — no pytest, no external dependencies.
"""

import importlib.machinery
import importlib.util
import logging
import logging.handlers
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SUPERVISOR_PATH = _REPO_ROOT / "crowdsec_cf_sync" / "main.py"

# Singleton: load the supervisor at most once across the whole test run.
# Each test file does `sup = load_supervisor()` at module-level; without
# caching, every import would add a fresh StreamHandler to the root logger,
# producing N-duplicated log lines per supervisor log call.
_CACHED_MODULE = None


class _NullHandler(logging.Handler):
    def emit(self, record):
        pass


def load_supervisor():
    """Return the supervisor module (singleton, logging neutralized).

    Tests share the same module instance and mutate module-level path constants
    via setattr in setUp / restore in tearDown. unittest runs serially, so no
    race condition.
    """
    global _CACHED_MODULE
    if _CACHED_MODULE is not None:
        return _CACHED_MODULE

    if not _SUPERVISOR_PATH.exists():
        raise RuntimeError(
            f"Supervisor not found at {_SUPERVISOR_PATH}. "
            "Run from a checkout of crowdsec-cf-sync."
        )

    # Silence the supervisor's logger: replace its StreamHandler with no-op.
    # We do this AFTER the module loads so _setup_logging completes normally,
    # then we wipe handlers on the returned logger.
    original_rfh = logging.handlers.RotatingFileHandler
    logging.handlers.RotatingFileHandler = lambda *a, **kw: _NullHandler()
    try:
        loader = importlib.machinery.SourceFileLoader(
            "_supervisor_under_test", str(_SUPERVISOR_PATH)
        )
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
    finally:
        logging.handlers.RotatingFileHandler = original_rfh

    # Strip stderr StreamHandler so supervisor logs don't pollute test output.
    module.log.handlers = [_NullHandler()]
    module.log.propagate = False

    _CACHED_MODULE = module
    return module
