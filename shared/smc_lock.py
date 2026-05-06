"""
Process-wide SMC session lock.

The ``smc-python`` SDK keeps its session state in a module-level singleton
(``from smc import session``). Login/logout mutate that singleton in place,
so two threads running ``session.login()`` and ``session.logout()`` against
different configs will corrupt each other:

  Thread A: session.login(domain="A") → ...mid-request API calls...
  Thread B: session.login(domain="B")        ← clobbers A's session id
  Thread A: engine.routing.all()             ← raises SMCConnectionError
                                              "No session found"
  Thread B: session.logout()                  ← logs A out too

This bug is silent under sync-worker gunicorn (one thread per worker) but
surfaces immediately under threaded workers (``-k gthread --threads N``)
and on the slow-by-design Engines cluster-detail page (multiple sequential
SDK calls).

Until the SDK gains thread-local sessions, the safe answer is to serialise
every SMC operation behind a single re-entrant lock. Throughput drops to
"one in-flight SMC op per worker process" — acceptable for an admin tool,
and the ``RLock`` keeps nested ``smc_session`` callers (e.g. a TLS deploy
that itself opens a sub-session in a helper) from deadlocking themselves.

Usage
-----
::

    from shared.smc_lock import smc_global_lock

    with smc_global_lock():
        session.login(...)
        try:
            ...do SMC work...
        finally:
            session.logout()

Or as the wrapper around an existing ``smc_session`` context manager.
"""
import logging
import threading
import time
from contextlib import contextmanager

log = logging.getLogger(__name__)

# Re-entrant so the same thread can nest smc_session calls without deadlocking
# (e.g. a webhook handler opens a session, then calls a helper that itself
# opens another). RLock is keyed by thread, not by call depth, so the second
# acquire is free for the same thread and blocks for everyone else.
_SMC_LOCK = threading.RLock()

# Tunable: how long to wait before giving up on the lock and surfacing a
# clear "another SMC op is in progress" error to the operator. 120 s is
# enough for any normal op (policy upload ~30-60 s, plus headroom) without
# letting a hung op queue indefinitely.
DEFAULT_TIMEOUT = 120


@contextmanager
def smc_global_lock(timeout: int = DEFAULT_TIMEOUT):
    """Acquire the process-wide SMC lock or raise.

    Raises:
      TimeoutError: another SMC op held the lock for longer than ``timeout``
                    seconds. The operator should retry; the route handler
                    should surface this as a 503-style "busy" response.
    """
    started = time.monotonic()
    acquired = _SMC_LOCK.acquire(timeout=timeout)
    if not acquired:
        raise TimeoutError(
            f"Could not acquire the SMC session lock within {timeout}s — "
            f"another SMC operation is still in progress. Retry in a moment."
        )
    waited_ms = int((time.monotonic() - started) * 1000)
    if waited_ms > 1000:
        log.info("smc_global_lock: waited %d ms before acquiring", waited_ms)
    try:
        yield
    finally:
        _SMC_LOCK.release()
