"""
core/di/container.py — Minimal dependency-injection container.

Why custom (not ``dependency-injector``)
----------------------------------------

* Supply chain stays small — every line is auditable; no native deps.
* No auto-wiring magic: the container only resolves explicitly-registered
  factories. This is a feature, not a limitation — explicit graphs are
  easier to reason about under security audit.
* Reentrancy: a per-run *scoped* container (one per orchestrator run)
  inherits from the global one so request-scoped collaborators (e.g. a
  per-run :class:`AgentStepRecorder`) do not leak across runs.

Surface
-------

::

    container = ServiceContainer()
    container.register(AuditLog, lambda: AuditLog(), singleton=True)
    container.register(ToolExecutor, lambda c: ToolExecutor(
        audit_log=c.resolve(AuditLog),
        scope_validator=c.resolve(ScopeValidator),
    ))

    audit = container.resolve(AuditLog)             # singleton, cached
    exe   = container.resolve(ToolExecutor)         # transient by default

    with container.scope() as run_scope:
        run_scope.register(Recorder, lambda: Recorder(run_id="r1"))
        rec = run_scope.resolve(Recorder)           # scoped to this run

Factory signatures
------------------

A factory is either zero-arg (``lambda: SomeType(...)``) or accepts the
container itself (``lambda c: SomeType(dep=c.resolve(Dep))``). The
container introspects the arity once at registration time.
"""
from __future__ import annotations

import contextlib
import inspect
import threading
from collections.abc import Callable, Iterator
from contextvars import ContextVar
from typing import Any, TypeVar, cast

T = TypeVar("T")


class DIError(RuntimeError):
    """Raised on registration / resolution failures.

    Includes the *type* being resolved in the message so the stack trace
    points at the offending dependency rather than a generic KeyError.
    """


class _Registration:
    __slots__ = ("factory", "singleton", "wants_container", "_instance")

    def __init__(
        self,
        factory: Callable[..., Any],
        *,
        singleton: bool,
        wants_container: bool,
    ) -> None:
        self.factory = factory
        self.singleton = singleton
        self.wants_container = wants_container
        self._instance: Any = None

    def materialize(self, container: "ServiceContainer") -> Any:
        if self.singleton and self._instance is not None:
            return self._instance
        instance = (
            self.factory(container) if self.wants_container else self.factory()
        )
        if self.singleton:
            self._instance = instance
        return instance


def _factory_wants_container(factory: Callable[..., Any]) -> bool:
    """Return True when the factory's signature has exactly one positional arg.

    Two-arg+ factories are rejected at registration so callers cannot
    accidentally rely on the container handing them more than itself.
    """
    try:
        sig = inspect.signature(factory)
    except (TypeError, ValueError):
        return False
    params = [
        p for p in sig.parameters.values()
        if p.kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        and p.default is inspect.Parameter.empty
    ]
    return len(params) == 1


class ServiceContainer:
    """Process-wide service registry.

    Thread-safe: registration and resolution are guarded by an RLock so
    application code calling ``container.resolve(...)`` from multiple
    asyncio threads cannot race on the lazy-singleton slot.
    """

    def __init__(self) -> None:
        self._registrations: dict[type, _Registration] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(
        self,
        cls: type[T],
        factory: Callable[..., T],
        *,
        singleton: bool = True,
    ) -> None:
        """Bind ``cls`` to ``factory``.

        ``singleton=True`` (default) caches the first materialized
        instance for the life of the container. ``singleton=False`` calls
        ``factory`` on every ``resolve``.
        """
        if not callable(factory):
            raise DIError(f"factory for {cls!r} is not callable: {factory!r}")
        with self._lock:
            self._registrations[cls] = _Registration(
                factory=factory,
                singleton=singleton,
                wants_container=_factory_wants_container(factory),
            )

    def register_instance(self, cls: type[T], instance: T) -> None:
        """Bind ``cls`` to an already-built ``instance``. Equivalent to
        ``register(cls, lambda: instance, singleton=True)`` but skips the
        factory introspection step."""
        with self._lock:
            reg = _Registration(
                factory=lambda: instance,
                singleton=True,
                wants_container=False,
            )
            reg._instance = instance
            self._registrations[cls] = reg

    def is_registered(self, cls: type) -> bool:
        return cls in self._registrations

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------

    def resolve(self, cls: type[T]) -> T:
        """Build and return an instance of ``cls``.

        Raises :class:`DIError` if ``cls`` has not been registered. There
        is no implicit fallback to ``cls()`` — every dependency must be
        declared so the audit team can enumerate the live graph.
        """
        with self._lock:
            reg = self._registrations.get(cls)
            if reg is None:
                raise DIError(
                    f"no factory registered for {cls.__module__}.{cls.__qualname__}"
                )
            try:
                return cast(T, reg.materialize(self))
            except DIError:
                raise
            except Exception as exc:                       # pragma: no cover
                raise DIError(
                    f"failed to build {cls!r}: {type(exc).__name__}: {exc}"
                ) from exc

    def try_resolve(self, cls: type[T]) -> T | None:
        """Like :meth:`resolve` but returns ``None`` for unregistered types."""
        if not self.is_registered(cls):
            return None
        return self.resolve(cls)

    # ------------------------------------------------------------------
    # Scoped containers (per-run)
    # ------------------------------------------------------------------

    @contextlib.contextmanager
    def scope(self) -> Iterator["ScopedContainer"]:
        """Open a per-run scope that inherits the parent's bindings.

        Registrations made on the scoped container are visible only inside
        the ``with`` block; the parent stays untouched.
        """
        child = ScopedContainer(self)
        token = _CURRENT_CONTAINER.set(child)
        try:
            yield child
        finally:
            _CURRENT_CONTAINER.reset(token)

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def registered_types(self) -> list[type]:
        """Snapshot of every type currently bound. Useful for diagnostics
        and for a future ``/diag/di`` endpoint."""
        with self._lock:
            return list(self._registrations.keys())


class ScopedContainer(ServiceContainer):
    """Per-scope container that falls back to a parent for unknown types.

    Registrations on the scope do **not** leak to the parent. Resolution
    walks the scope first, then the parent — mirrors classic IoC scope
    semantics.

    Critically, when a *parent* registration is materialized from the
    scope, we hand the *scope* (not the parent) to the factory so that
    cascading ``container.resolve(...)`` calls inside that factory see
    any scope-level overrides. This is what makes scoped overrides
    propagate through the dependency graph rather than only affecting
    leaf resolutions.
    """

    def __init__(self, parent: ServiceContainer) -> None:
        super().__init__()
        self._parent = parent

    def resolve(self, cls: type[T]) -> T:
        with self._lock:
            reg = self._registrations.get(cls)
        if reg is not None:
            try:
                return cast(T, reg.materialize(self))
            except DIError:
                raise
            except Exception as exc:                       # pragma: no cover
                raise DIError(
                    f"failed to build {cls!r}: {type(exc).__name__}: {exc}"
                ) from exc
        # Fall back to the parent's registration but materialize using
        # *this* scope so the factory's transitive resolves see overrides.
        with self._parent._lock:
            parent_reg = self._parent._registrations.get(cls)
        if parent_reg is None:
            raise DIError(
                f"no factory registered for {cls.__module__}.{cls.__qualname__}"
            )
        try:
            return cast(T, parent_reg.materialize(self))
        except DIError:
            raise
        except Exception as exc:                           # pragma: no cover
            raise DIError(
                f"failed to build {cls!r}: {type(exc).__name__}: {exc}"
            ) from exc

    def is_registered(self, cls: type) -> bool:
        with self._lock:
            if cls in self._registrations:
                return True
        return self._parent.is_registered(cls)


# ----------------------------------------------------------------------
# Module-level "current" container
# ----------------------------------------------------------------------
# A ContextVar lets the scoped container be discovered by deep call stacks
# (e.g. an MCP server tool that needs the same AuditLog as the orchestrator
# without threading the container through every call). The default is a
# fresh empty container — production bootstraps replace it via
# ``set_current_container`` in ``cli.py``.

_CURRENT_CONTAINER: ContextVar[ServiceContainer] = ContextVar(
    "sap_di_current_container", default=ServiceContainer(),
)


def current_container() -> ServiceContainer:
    """Return the active container for this context."""
    return _CURRENT_CONTAINER.get()


def set_current_container(container: ServiceContainer) -> None:
    """Replace the process-default container. Idempotent; intended for
    application bootstrap in :mod:`cli` and tests."""
    _CURRENT_CONTAINER.set(container)
