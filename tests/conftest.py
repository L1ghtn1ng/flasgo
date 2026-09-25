import logging
import sys
from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def _restore_flasgo_logger() -> Iterator[None]:
    """Lifespan startup calls configure_logging(), which mutates the process-wide ``flasgo`` logger."""
    logger = logging.getLogger("flasgo")
    handlers, level, propagate = list(logger.handlers), logger.level, logger.propagate
    yield
    logger.handlers[:] = handlers
    logger.setLevel(level)
    logger.propagate = propagate


@pytest.fixture
def restore_import_state() -> Iterator[None]:
    """Undo sys.path and sys.modules changes made by importing throwaway app modules (for example via the CLI)."""
    import flasgo.cli as cli_module

    path = list(sys.path)
    modules = set(sys.modules)
    namespace_roots = dict(cli_module._CLI_NAMESPACE_ROOTS)
    root_modules = dict(cli_module._CLI_ROOT_MODULES)
    yield
    sys.path[:] = path
    for name in set(sys.modules) - modules:
        del sys.modules[name]
    cli_module._CLI_NAMESPACE_ROOTS.clear()
    cli_module._CLI_NAMESPACE_ROOTS.update(namespace_roots)
    cli_module._CLI_ROOT_MODULES.clear()
    cli_module._CLI_ROOT_MODULES.update(root_modules)
