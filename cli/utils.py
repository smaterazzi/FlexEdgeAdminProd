"""
Shared CLI utilities for FlexEdgeAdmin.
"""

import contextlib
import io


def suppress_stdout(active):
    """
    Return a context manager that suppresses stdout when ``active`` is True.

    Used by the CLI modules to silence human-readable print output while
    ``--json`` mode is active, keeping the emitted JSON clean.
    """
    if active:
        return contextlib.redirect_stdout(io.StringIO())
    return contextlib.nullcontext()
